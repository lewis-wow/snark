import { describe, expect, test } from 'vitest';
import { Kzg } from '../../../src/PolynomialCommitmentScheme/Kzg';
import { evalPolyAt } from '../../../src/utils/evalPolyAt';

describe('Kzg', () => {
  test('works', () => {
    const kzg = new Kzg();

    // f(x) = 5 + 4x + 3x^2 + 2x^3 + x^4
    const f_coeffs = [5n, 4n, 3n, 2n, 1n];

    const { pp, alpha_G2 } = kzg.setup({ degree: f_coeffs.length - 1 });
    const com_f = kzg.commit({
      pp,
      f_coeffs,
    });

    // We want to evaluate the polynomial at x = 5
    const u = 5n;

    // v = f(5)
    const v = evalPolyAt(Kzg.Fr, f_coeffs, u);

    const com_q = kzg.prove({ pp, f_coeffs, u });

    const isValid = kzg.verify({
      com_f,
      com_q,
      u,
      v,
      alpha_G2,
    });

    expect(isValid).toBe(true);
  });
});
