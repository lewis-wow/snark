import { assert } from '../assert.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';

export type PointG1 = InstanceType<typeof bls12_381.G1.Point>;
export type PointG2 = InstanceType<typeof bls12_381.G2.Point>;

export type Setup = { pp: PointG1[]; alpha_G2: PointG2 };

export class Kzg {
  static readonly G1 = bls12_381.G1.Point.BASE;
  static readonly G2 = bls12_381.G2.Point.BASE;
  static readonly G1_ZERO = bls12_381.G1.Point.ZERO;
  static readonly Fr = bls12_381.fields.Fr;
  static readonly ZERO = 0n;

  /**
   * Creates public parameters using trusted setup.
   *
   * S(C) = (S_p, S_v)
   * S_p = pp = parameters for prover.
   * S_v = alpha_G2 = parameter for verifier.
   */
  protected _setup(opts: { degree: number; alpha: bigint }): Setup {
    const { degree, alpha } = opts;
    assert(degree > 0);

    // G1 is the base point (generator) for the first cryptographic group of the BLS12-381 curve.
    // Its coordinates are in the base field F_p making it smaller and computationally faster.
    // We use G1 to create the prover's public parameters (pp) and all polynomial commitments.
    const G1 = Kzg.G1;

    // G2 is the base point (generator) for the second cryptographic group of the BLS12-381 curve.
    // Its coordinates are in the extension field F_p^2 making it larger and slower to compute.
    // We need G2 specifically to create the verifier's key (alpha_G2) which is required for the bilinear pairing check.
    const G2 = Kzg.G2;

    // pp = [H_0 = G, H_1 = a*G, H_2 = a^2*G, ..., H_d = a^d*G]
    let currentAlpha = 1n;
    const pp: PointG1[] = [];
    for (let i = 0; i < degree + 1; i++) {
      const point = G1.multiply(currentAlpha);
      currentAlpha = Kzg.Fr.mul(currentAlpha, alpha);
      pp.push(point);
    }

    // alpha_G2 is the secret scalar 'a' masked as a point on the G2 elliptic curve.
    // It is created through scalar multiplication of the G2 generator point by 'a'.
    // The Elliptic Curve Discrete Logarithm Problem (ECDLP) guarantees that finding 'a' from G2 and alpha_G2 is computationally infeasible.
    const alpha_G2 = G2.multiply(alpha);

    return { pp, alpha_G2 };
  }

  /**
   * Creates public parameters using trusted setup.
   *
   * S(C) = (S_p, S_v)
   * S_p = pp = parameters for prover.
   * S_v = alpha_G2 = parameter for verifier.
   */
  setup(opts: { degree: number }): Setup {
    const { degree } = opts;
    assert(degree > 0);

    let alpha = Kzg.Fr.fromBytes(
      crypto.getRandomValues(new Uint8Array(Kzg.Fr.BYTES)),
    );

    const { pp, alpha_G2 } = this._setup({ degree, alpha });

    alpha = null;

    return { pp, alpha_G2 };
  }

  /**
   * Creates prover's binding, not hiding, commitment com_f = f(alfa) * G.
   * Hiding commitment requires secret random parameter r.
   */
  commit(opts: { pp: PointG1[]; f_coeffs: bigint[] }): PointG1 {
    const { pp, f_coeffs } = opts;
    assert(pp.length === f_coeffs.length);

    // com_f = f(alfa) * G;
    // f(x) = f0 + f1*x + f2*x^2 + ... + fd*x^d
    //    => com_f = f0*H0 + f1*H1 + f2*H2 + ... + fd*Hd = f(alfa) * G
    let com_f = Kzg.G1_ZERO;
    for (let i = 0; i < pp.length; i++) {
      const term = pp[i].multiply(f_coeffs[i]);
      com_f = com_f.add(term);
    }

    return com_f;
  }

  /**
   * Computes q(X) and creates a commitment of q(X) = com_q.
   * The proof commitment is short, constant size in GF.
   * An expensive computation for large polynomial degree d.
   *
   * A number a is a root of a polynomial P
   * if and only if the linear polynomial x − a divides P,
   * that is if there is another polynomial Q such that P = (x − a) Q.
   * @see https://en.wikipedia.org/wiki/Polynomial
   *
   * f(u) = v
   * <=> u is root of F = f - v
   * <=> (X - u) divides F = f - v
   * <=> Exist q, so q(X) * (X - u) = f(X) - v
   *
   * This division only works without a remainder if v is the true evaluation of f(u).
   */
  prove(opts: { pp: PointG1[]; f_coeffs: bigint[]; u: bigint }): PointG1 {
    const { pp, f_coeffs, u } = opts;

    // The quotient polynomial q(x) has a degree one less than f(x)
    const q_coeffs = new Array<bigint>(f_coeffs.length - 1);

    // Calculate q(x) coefficients using synthetic division
    let carry = Kzg.ZERO;
    for (let i = f_coeffs.length - 1; i > 0; i--) {
      carry = Kzg.Fr.add(f_coeffs[i], Kzg.Fr.mul(u, carry));
      q_coeffs[i - 1] = carry;
    }

    // The proof is the commitment to the quotient polynomial q(x)
    const q_pp = pp.slice(0, q_coeffs.length);

    return this.commit({ pp: q_pp, f_coeffs: q_coeffs });
  }

  /**
   * Verifies if the proof is valid.
   *
   * (alpha - u) * com_q = com_f - v * G
   * <=> (alpha - u) * q(alpha) = f(alpha) * G - v * G
   * <=> (alpha - u) * q(alpha) = f(alpha) - v
   * <=> q(alpha) * (alpha - u) = f(alpha) - v
   *
   * Checks the pairing equality:
   * e(com_q, alpha*G2 - u*G2) == e(com_f - v*G1, G2)
   */
  verify(opts: {
    com_f: PointG1;
    com_q: PointG1;
    u: bigint;
    v: bigint;
    alpha_G2: PointG2;
  }): boolean {
    const { com_f, com_q, u, v, alpha_G2 } = opts;

    const G1 = Kzg.G1;
    const G2 = Kzg.G2;

    // Bilinear property: e(aG_1, bG_2) = e(G_1, G_2)^{ab}

    // e(com_q, alpha*G_2 - u*G_2)
    // com_q = q(alfa) * G_1
    // e(q(alfa) * G_1, (alpha-u) * G_2)
    // Applying bilinear property: e(G_1, G_2)^{q(alfa) * (alpha-u)}
    const pairing2 = bls12_381.pairing(
      com_q,
      // alpha*G2 - u*G2
      alpha_G2.subtract(G2.multiply(u)),
    );

    // e(com_f - v*G_1, G_2)
    // com_f = f(alfa) * G_1
    // e((f(alfa) - v) * G_1, G_2)
    // Applying bilinear property: e(G_1, G_2)^{f(alfa) - v}
    const pairing1 = bls12_381.pairing(
      // com_f - v*G1
      com_f.subtract(G1.multiply(v)),
      G2,
    );

    // e(G_1, G_2)^{q(alfa) * (alpha-u)} = e(G_1, G_2)^{f(alfa) - v}
    // <=> q(alfa) * (alpha-u) = f(alfa) - v
    return bls12_381.fields.Fp12.eql(pairing1, pairing2);
  }
}
