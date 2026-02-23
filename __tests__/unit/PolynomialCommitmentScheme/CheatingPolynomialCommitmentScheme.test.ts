import { describe, expect, test } from 'vitest';
import { CheatingPolynomialCommitmentScheme } from '../../../src/PolynomialCommitmentScheme/CheatingPolynomialCommitmentScheme';

describe('CheatingPolynomialCommitmentScheme', () => {
  test('works', () => {
    const pcs = new CheatingPolynomialCommitmentScheme();

    // f(x) = 5 + 4x + 3x^2 + 2x^3 + x^4
    const f = pcs.field.newVectorFrom([5n, 4n, 3n, 2n, 1n]);

    const { pp, alpha_G2, alpha } = pcs.setup({ degree: f.length - 1 });
    const com_f = pcs.commit({
      pp,
      coefficients: f.toValues(),
    });

    // We want to evaluate the polynomial at x = 5
    const u = 5n;

    // v = f(5)
    const v = pcs.field.evalPolyAt(f, u);
    const vFake = 999n;

    const com_q = pcs.prove({
      pp,
      f_coefficients: f.toValues(),
      u,
      alpha,
      vFake,
    });

    const isValid = pcs.verify({
      com_f,
      com_q,
      u,
      v: vFake,
      alpha_G2,
    });

    expect(isValid).toBe(true);
    expect(vFake).not.toBe(v);
  });
});
