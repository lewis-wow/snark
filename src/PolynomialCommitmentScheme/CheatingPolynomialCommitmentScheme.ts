import { bls12_381 } from '@noble/curves/bls12-381.js';
import { assert } from '../assert.js';
import {
  PointG1,
  PolynomialCommitmentScheme,
  Setup,
} from './PolynomialCommitmentScheme.js';

const Fr = bls12_381.fields.Fr;

export class CheatingPolynomialCommitmentScheme extends PolynomialCommitmentScheme {
  override setup(opts: { degree: number }): Setup & { alpha: bigint } {
    const { degree } = opts;
    assert(degree > 0);

    const alpha = this.field.rand();

    const { pp, alpha_G2 } = this._setup({ degree, alpha });

    return { pp, alpha_G2, alpha };
  }

  override prove(opts: {
    pp: PointG1[];
    f_coefficients: bigint[];
    u: bigint;
    vFake: bigint;
    alpha: bigint;
  }): PointG1 {
    const { f_coefficients, u, vFake, alpha } = opts;

    // Evaluate the actual polynomial at the secret alpha
    let f_alpha = 0n;
    let currentAlphaPow = 1n;
    for (let i = 0; i < f_coefficients.length; i++) {
      const term = Fr.mul(f_coefficients[i], currentAlphaPow);
      f_alpha = Fr.add(f_alpha, term);
      currentAlphaPow = Fr.mul(currentAlphaPow, alpha);
    }

    // Calculate qFake = (f(alpha) - vFake) / (alpha - u)
    const numerator = Fr.sub(f_alpha, vFake);
    const denominator = Fr.sub(alpha, u);
    const qFake = Fr.div(numerator, denominator);

    // Create the fake proof commitment by multiplying the G1 generator by qFake
    const G1 = bls12_381.G1.Point.BASE;

    return G1.multiply(qFake);
  }
}
