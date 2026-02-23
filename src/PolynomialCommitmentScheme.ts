import * as galois from '@guildofweavers/galois';
import { assert } from './assert.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';

export type PointG1 = InstanceType<typeof bls12_381.G1.Point>;
export type PointG2 = InstanceType<typeof bls12_381.G2.Point>;

export class PolynomialCommitmentScheme {
  readonly field: galois.FiniteField;

  constructor() {
    this.field = galois.createPrimeField(bls12_381.fields.Fr.ORDER);
  }

  /**
   * Creates public parameters using trusted setup.
   */
  setup(opts: { degree: number }): { pp: PointG1[]; alpha_G2: PointG2 } {
    const { degree } = opts;

    const G1 = bls12_381.G1.Point.BASE;
    const G2 = bls12_381.G2.Point.BASE;

    // Sample random alfa
    const a = this.field.rand();

    // pp = [H_0 = G, H_1 = a*G, H_2 = a^2*G, ..., H_d = a^d*G]
    let currentAlpha = 1n;
    const pp: PointG1[] = [];
    for (let i = 0; i < degree + 1; i++) {
      const point = G1.multiply(currentAlpha);
      currentAlpha = this.field.mul(currentAlpha, a);
      pp.push(point);
    }

    // Secret value for pairing.
    const alpha_G2 = G2.multiply(a);

    // Remove alfa (trusted setup).
    // We have to trust that the prover deletes alfa.

    return { pp, alpha_G2 };
  }

  /**
   * Creates prover's binding, not hiding, commitment com_f = f(alfa) * G.
   * Hiding commitment requires secret random parameter r.
   */
  commit(opts: { pp: PointG1[]; coefficients: bigint[] }): PointG1 {
    const { pp, coefficients } = opts;
    assert(pp.length === coefficients.length);

    // com_f = f(alfa) * G;
    // f(x) = f0 + f1*x + f2*x^2 + ... + fd*x^d
    //    => com_f = f0*H0 + f1*H1 + f2*H2 + ... + fd*Hd = f(alfa) * G
    let com_f = bls12_381.G1.Point.ZERO;
    for (let i = 0; i < pp.length; i++) {
      const term = pp[i].multiply(coefficients[i]);
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
   * <=> (X - u) divides F
   * <=> Exist q, so q(X) * (X - u) = f(X) - v
   */
  prove(opts: { pp: PointG1[]; f_coefficients: bigint[]; u: bigint }): PointG1 {
    const { pp, f_coefficients, u } = opts;

    // The quotient polynomial q(x) has a degree one less than f(x)
    const q_coefficients = new Array<bigint>(f_coefficients.length - 1);

    // Calculate q(x) coefficients using synthetic division
    let carry = this.field.zero;
    for (let i = f_coefficients.length - 1; i > 0; i--) {
      carry = this.field.add(f_coefficients[i], this.field.mul(u, carry));
      q_coefficients[i - 1] = carry;
    }

    // The proof is the commitment to the quotient polynomial q(x)
    const q_pp = pp.slice(0, q_coefficients.length);

    return this.commit({ pp: q_pp, coefficients: q_coefficients });
  }

  /**
   * Verifies if the proof is valid.
   *
   * (alfa - u) * com_q = com_f - v * G
   * <=> (X - u) * q(X) = f(X) * G - v * G
   * <=> (X - u) * q(X) = f(X) - v
   * <=> q(X) * (X - u) = f(X) - v
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

    const G1 = bls12_381.G1.Point.BASE;
    const G2 = bls12_381.G2.Point.BASE;

    const v_G1 = G1.multiply(v);
    const lhs_G1 = com_f.subtract(v_G1);

    const u_G2 = G2.multiply(u);
    const rhs_G2 = alpha_G2.subtract(u_G2);

    const pairing1 = bls12_381.pairing(lhs_G1, G2);
    const pairing2 = bls12_381.pairing(com_q, rhs_G2);

    return bls12_381.fields.Fp12.eql(pairing1, pairing2);
  }
}
