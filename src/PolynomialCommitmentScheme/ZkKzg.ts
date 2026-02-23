import { assert } from '../assert.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';

export type PointG1 = InstanceType<typeof bls12_381.G1.Point>;
export type PointG2 = InstanceType<typeof bls12_381.G2.Point>;

export type Setup = {
  pp_G1: PointG1[];
  pp_H: PointG1[];
  alpha_G2: PointG2;
  H: PointG1;
};

export class ZkKzg {
  static readonly G1 = bls12_381.G1.Point.BASE;
  static readonly G2 = bls12_381.G2.Point.BASE;
  static readonly G1_ZERO = bls12_381.G1.Point.ZERO;
  static readonly Fr = bls12_381.fields.Fr;
  static readonly ZERO = 0n;

  private _rand(): bigint {
    return ZkKzg.Fr.fromBytes(
      crypto.getRandomValues(new Uint8Array(ZkKzg.Fr.BYTES)),
    );
  }

  /**
   * Creates public parameters using trusted setup.
   *
   * S(C) = (S_p, S_v)
   * S_p = pp = parameters for prover.
   * S_v = alpha_G2 = parameter for verifier.
   */
  protected _setup(opts: {
    degree: number;
    alpha: bigint;
    beta: bigint;
  }): Setup {
    const { degree, alpha, beta } = opts;
    assert(degree > 0);

    // G1 is the base point (generator) for the first cryptographic group of the BLS12-381 curve.
    // Its coordinates are in the base field F_p making it smaller and computationally faster.
    // We use G1 to create the prover's public parameters (pp) and all polynomial commitments.
    const G1 = ZkKzg.G1;

    // G2 is the base point (generator) for the second cryptographic group of the BLS12-381 curve.
    // Its coordinates are in the extension field F_p^2 making it larger and slower to compute.
    // We need G2 specifically to create the verifier's key (alpha_G2) which is required for the bilinear pairing check.
    const G2 = ZkKzg.G2;

    const H = G1.multiply(beta);

    // pp = [H_0 = G, H_1 = a*G, H_2 = a^2*G, ..., H_d = a^d*G]
    let currentAlpha = 1n;
    const pp_G1: PointG1[] = [];
    const pp_H: PointG1[] = [];

    for (let i = 0; i < degree + 1; i++) {
      pp_G1.push(G1.multiply(currentAlpha));
      pp_H.push(H.multiply(currentAlpha));
      currentAlpha = ZkKzg.Fr.mul(currentAlpha, alpha);
    }

    // alpha_G2 is the secret scalar 'a' masked as a point on the G2 elliptic curve.
    // It is created through scalar multiplication of the G2 generator point by 'a'.
    // The Elliptic Curve Discrete Logarithm Problem (ECDLP) guarantees that finding 'a' from G2 and alpha_G2 is computationally infeasible.
    const alpha_G2 = G2.multiply(alpha);

    return { pp_G1, pp_H, alpha_G2, H };
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

    let alpha = this._rand();
    let beta = this._rand();

    const { pp_G1, pp_H, alpha_G2, H } = this._setup({ degree, alpha, beta });

    alpha = null;
    beta = null;

    return { pp_G1, pp_H, alpha_G2, H };
  }

  /**
   * Creates prover's binding, not hiding, commitment com_f = f(alfa) * G.
   * Hiding commitment requires secret random parameter r.
   */
  commit(opts: {
    pp_G1: PointG1[];
    pp_H: PointG1[];
    f_coeffs: bigint[];
    r_coeffs: bigint[];
  }): PointG1 {
    const { pp_G1, pp_H, f_coeffs, r_coeffs } = opts;
    assert(pp_G1.length === f_coeffs.length);
    assert(pp_H.length === r_coeffs.length);

    // com_f = f(alfa) * G;
    // f(x) = f0 + f1*x + f2*x^2 + ... + fd*x^d
    //    => com_f = f0*H0 + f1*H1 + f2*H2 + ... + fd*Hd = f(alfa) * G
    let com_f = ZkKzg.G1_ZERO;
    for (let i = 0; i < pp_G1.length; i++) {
      const termG1 = pp_G1[i].multiply(f_coeffs[i]);
      const termH = pp_H[i].multiply(r_coeffs[i]);

      com_f = com_f.add(termG1).add(termH);
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
  prove(opts: {
    pp_G1: PointG1[];
    pp_H: PointG1[];
    f_coeffs: bigint[];
    r_coeffs: bigint[];
    u: bigint;
  }): PointG1 {
    const { pp_G1, pp_H, f_coeffs, r_coeffs, u } = opts;

    const q_f_coeffs = new Array<bigint>(f_coeffs.length - 1);
    let carry_f = ZkKzg.ZERO;
    for (let i = f_coeffs.length - 1; i > 0; i--) {
      carry_f = ZkKzg.Fr.add(f_coeffs[i], ZkKzg.Fr.mul(u, carry_f));
      q_f_coeffs[i - 1] = carry_f;
    }

    const q_r_coeffs = new Array<bigint>(r_coeffs.length - 1);
    let carry_r = ZkKzg.ZERO;
    for (let i = r_coeffs.length - 1; i > 0; i--) {
      carry_r = ZkKzg.Fr.add(r_coeffs[i], ZkKzg.Fr.mul(u, carry_r));
      q_r_coeffs[i - 1] = carry_r;
    }

    const q_pp_G1 = pp_G1.slice(0, q_f_coeffs.length);
    const q_pp_H = pp_H.slice(0, q_r_coeffs.length);

    return this.commit({
      pp_G1: q_pp_G1,
      pp_H: q_pp_H,
      f_coeffs: q_f_coeffs,
      r_coeffs: q_r_coeffs,
    });
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
    v_r: bigint;
    alpha_G2: PointG2;
    H: PointG1;
  }): boolean {
    const { com_f, com_q, u, v, v_r, alpha_G2, H } = opts;

    const G1 = ZkKzg.G1;
    const G2 = ZkKzg.G2;

    // Bilinear property: e(aG_1, bG_2) = e(G_1, G_2)^{ab}

    // e(com_q, alpha*G_2 - u*G_2)
    // com_q = q(alpha) * G_1 + q_r(alpha) * H
    // e(q(alpha) * G_1 + q_r(alpha) * H, (alpha - u) * G_2)
    // Applying bilinear property: e(G1, G2)^{q_f(alpha) * (alpha - u)} * e(H, G2)^{q_r(alpha) * (alpha - u)}
    const pairing2 = bls12_381.pairing(
      com_q,
      // alpha*G2 - u*G2
      alpha_G2.subtract(G2.multiply(u)),
    );

    // e(com_f - v * G_1, G_2)
    // com_f = f(alpha) * G1 + r(alpha) * H
    // e((f(alpha) - v)*G1 + (r(alpha) - v_r)*H, G2)
    // Applying bilinear property: e(G1, G2)^(f(alpha) - v) * e(H, G2)^(r(alpha) - v_r)
    const pairing1 = bls12_381.pairing(
      // com_f - v*G1 - v_r*H
      com_f.subtract(G1.multiply(v)).subtract(H.multiply(v_r)),
      G2,
    );

    // e(G1, G2)^{q_f(alpha) * (alpha - u)} * e(H, G2)^{q_r(alpha) * (alpha - u)} = e(G1, G2)^(f(alpha) - v) * e(H, G2)^(r(alpha) - v_r)
    // <=>
    return bls12_381.fields.Fp12.eql(pairing1, pairing2);
  }
}
