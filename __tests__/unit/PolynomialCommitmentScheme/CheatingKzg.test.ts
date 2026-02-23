import { describe, expect, test } from 'vitest';
import { CheatingKzg } from '../../../src/PolynomialCommitmentScheme/CheatingKzg';
import { evalPolyAt } from '../../../src/utils/evalPolyAt';

describe('CheatingKzg', () => {
  test('Fake proof', () => {
    const cheatingKzg = new CheatingKzg();

    // f(x) = 5 + 4x + 3x^2 + 2x^3 + x^4
    const f_coeffs = [5n, 4n, 3n, 2n, 1n];

    const { pp, alpha_G2, alpha } = cheatingKzg.setup({
      degree: f_coeffs.length - 1,
    });

    const com_f = cheatingKzg.commit({
      pp,
      f_coeffs,
    });

    // We want to evaluate the polynomial at x = 5
    const u = 5n;

    // v = f(5)
    const v = evalPolyAt(CheatingKzg.Fr, f_coeffs, u);
    const vFake = 999n;

    const com_q = cheatingKzg.prove({
      pp,
      f_coeffs,
      u,
      alpha,
      vFake,
    });

    const isValid = cheatingKzg.verify({
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
