export const assert = (assertion: boolean): void => {
  if (assertion === false) {
    throw new Error('Assertion failed.');
  }
};
