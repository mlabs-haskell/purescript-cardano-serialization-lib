"use strict";

// eslint-disable-next-line no-unused-vars
import * as CSL from "@mlabs-haskell/cardano-serialization-lib-gc";

// Pass in a function and its list of arguments, that is expected to fail on evaluation, wraps in Either
// eslint-disable-next-line no-unused-vars
function errorableToPurs(f, ...vars) {
  try {
    return f(...vars);
  } catch (err) {
    return null;
  }
}
