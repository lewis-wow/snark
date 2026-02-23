import { describe, expect, test } from 'vitest';
import { ZkKzg } from '../../../src/PolynomialCommitmentScheme/ZkKzg';
import { evalPolyAt } from '../../../src/utils/evalPolyAt';
import { rand } from '../../../src/utils/rand';

describe('ZkKzg', () => {
  test('works', () => {
    const zkKzg = new ZkKzg();

    // f(x) = 5 + 4x + 3x^2 + 2x^3 + x^4
    const f_coeffs = [5n, 4n, 3n, 2n, 1n];
    // r(x) = 1 + 2x + 3x^2 + 4x^3 + 5x^4
    const r_coeffs = Array.from({ length: f_coeffs.length }, () =>
      rand(ZkKzg.Fr),
    );

    const { pp_G1, pp_H, alpha_G2, H } = zkKzg.setup({
      degree: f_coeffs.length - 1,
    });

    const com_f = zkKzg.commit({
      pp_G1,
      pp_H,
      f_coeffs,
      r_coeffs,
    });

    // We want to evaluate the polynomial at x = 5
    const u = 5n;

    // v = f(5)
    const v = evalPolyAt(ZkKzg.Fr, f_coeffs, u);
    // v_r = r(5)
    const v_r = evalPolyAt(ZkKzg.Fr, r_coeffs, u);

    const com_q = zkKzg.prove({ pp_G1, pp_H, f_coeffs, r_coeffs, u });

    const isValid = zkKzg.verify({
      com_f,
      com_q,
      u,
      v,
      v_r,
      alpha_G2,
      H,
    });

    expect(isValid).toBe(true);
  });

  test('commitments to the same polynomial are completely unpredictable', () => {
    const zkKzg = new ZkKzg();

    // The prover's secret polynomial remains the exact same
    const f_coeffs = [5n, 4n, 3n, 2n, 1n];

    // We generate two entirely different random blinding polynomials
    // We generate new polynomial for each new f polynomial commitment.
    const r1_coeffs = Array.from({ length: f_coeffs.length }, () =>
      rand(ZkKzg.Fr),
    );
    const r2_coeffs = Array.from({ length: f_coeffs.length }, () =>
      rand(ZkKzg.Fr),
    );

    const { pp_G1, pp_H } = zkKzg.setup({
      degree: f_coeffs.length - 1,
    });

    // Generate the first commitment
    const com_f1 = zkKzg.commit({
      pp_G1,
      pp_H,
      f_coeffs,
      r_coeffs: r1_coeffs,
    });

    // Generate a second commitment to the SAME secret data
    const com_f2 = zkKzg.commit({
      pp_G1,
      pp_H,
      f_coeffs,
      r_coeffs: r2_coeffs,
    });

    // The verifier cannot link the commitments because the blinding factors randomize the curve points
    expect(com_f1.equals(com_f2)).toBe(false);
  });
});
