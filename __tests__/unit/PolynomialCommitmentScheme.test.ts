import { describe, expect, test } from 'vitest';
import { PolynomialCommitmentScheme } from '../../src/PolynomialCommitmentScheme';

describe('PolynomialCommitmentScheme', () => {
  test('works', () => {
    const pcs = new PolynomialCommitmentScheme();

    // f(x) = 5 + 4x + 3x^2 + 2x^3 + x^4
    const f = pcs.field.newVectorFrom([5n, 4n, 3n, 2n, 1n]);

    const { pp, alpha_G2 } = pcs.setup({ degree: f.length - 1 });
    const com_f = pcs.commit({
      pp,
      coefficients: f.toValues(),
    });

    // We want to evaluate the polynomial at x = 5
    const u = 5n;

    // v = f(5)
    const v = pcs.field.evalPolyAt(f, u);

    const com_q = pcs.prove({ pp, f_coefficients: f.toValues(), u });

    const isValid = pcs.verify({
      com_f,
      com_q,
      u,
      v,
      alpha_G2,
    });

    expect(isValid).toBe(true);
  });
});
