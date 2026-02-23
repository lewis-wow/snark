import { IField } from '@noble/curves/abstract/modular.js';
import { mulPoly } from './mulPoly.js';
import { addPoly } from './addPoly.js';

export const lagrangeInterpolation = (
  Fr: IField<bigint>,
  points: { x: bigint; y: bigint }[],
): bigint[] => {
  let result = [0n];

  for (let i = 0; i < points.length; i++) {
    let basis = [1n];
    let denominator = 1n;

    for (let j = 0; j < points.length; j++) {
      if (i !== j) {
        // basis *= (x - x_j)
        basis = mulPoly(Fr, basis, [Fr.neg(points[j].x), 1n]);

        // denominator *= (x_i - x_j)
        const diff = Fr.sub(points[i].x, points[j].x);
        denominator = Fr.mul(denominator, diff);
      }
    }

    const invDenom = Fr.inv(denominator);
    const termY = Fr.mul(points[i].y, invDenom);
    const termPoly = mulPoly(Fr, basis, [termY]);

    result = addPoly(Fr, result, termPoly);
  }

  // Clean up trailing zeros
  while (result.length > 0 && result[result.length - 1] === 0n) {
    result.pop();
  }

  return result;
};
