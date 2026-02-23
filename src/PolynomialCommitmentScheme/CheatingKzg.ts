import { bls12_381 } from '@noble/curves/bls12-381.js';
import { assert } from '../assert.js';
import { Kzg, PointG1, Setup } from './Kzg.js';
import { rand } from '../utils/rand.js';

export class CheatingKzg extends Kzg {
  override setup(opts: { degree: number }): Setup & { alpha: bigint } {
    const { degree } = opts;
    assert(degree > 0);

    const alpha = rand(Kzg.Fr);

    const { pp, alpha_G2 } = this._setup({ degree, alpha });

    return { pp, alpha_G2, alpha };
  }

  override prove(opts: {
    pp: PointG1[];
    f_coeffs: bigint[];
    u: bigint;
    vFake: bigint;
    alpha: bigint;
  }): PointG1 {
    const { f_coeffs, u, vFake, alpha } = opts;

    // Evaluate the actual polynomial at the secret alpha
    let f_alpha = 0n;
    let currentAlphaPow = 1n;
    for (let i = 0; i < f_coeffs.length; i++) {
      const term = Kzg.Fr.mul(f_coeffs[i], currentAlphaPow);
      f_alpha = Kzg.Fr.add(f_alpha, term);
      currentAlphaPow = Kzg.Fr.mul(currentAlphaPow, alpha);
    }

    // Calculate qFake = (f(alpha) - vFake) / (alpha - u)
    const numerator = Kzg.Fr.sub(f_alpha, vFake);
    const denominator = Kzg.Fr.sub(alpha, u);
    const qFake = Kzg.Fr.div(numerator, denominator);

    // Create the fake proof commitment by multiplying the G1 generator by qFake
    const G1 = bls12_381.G1.Point.BASE;

    return G1.multiply(qFake);
  }
}
