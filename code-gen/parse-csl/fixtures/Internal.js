import * as csl from "@mlabs-haskell/cardano-serialization-lib-gc";

const clone = x => {
  if (typeof x.to_bytes === 'function' &&
      typeof x.constructor.from_bytes === 'function') {
    return x.constructor.from_bytes(x.to_bytes());
  } else {
    return x;
  }
};

export const _toBytes = x => x.to_bytes();
export const _fromBytes = key => nothing => just => bytes => {
  try {
    return just(csl[key].from_bytes(bytes));
  } catch (_) {
    return nothing;
  }
};

export const _packListContainer = containerClass => elems => {
  const container = csl[containerClass].new();
  for (let elem of elems) {
    container.add(clone(elem));
  }
  return container;
};

export const _unpackListContainer = container => {
  const res = [];
  const len = container.len();
  for (let i = 0; i < len; i++) {
    res.push(container.get(i));
  }
  return res;
};

export const _packMapContainer = containerClass => elems => {
  const container = csl[containerClass].new();
  for (let elem of elems) {
    container.insert(clone(elem.key), clone(elem.value));
  }
  return container;
};

export const _unpackMapContainer = container => {
  const keys = _unpackListContainer(container.keys());
  const res = [];
  for (let key of keys) {
    res.push({ key, value: container.get(key) });
  }
  return res;
};

export const _cslFromJson = className => nothing => just => json => {
  try {
    return just(csl[className].from_json(json));
  } catch (e) {
    return nothing;
  }
};

export const _cslToJson = x => JSON.parse(x.to_json());
