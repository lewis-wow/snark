import { IField } from '@noble/curves/abstract/modular.js';

export const evalPolyAt = (
  Fr: IField<bigint>,
  coefficients: bigint[],
  x: bigint,
): bigint => {
  return coefficients.reduceRight((accumulator, current) => {
    const accTimesX = Fr.mul(accumulator, x);
    return Fr.add(accTimesX, current);
  }, Fr.ZERO);
};
