// Small DOM helpers. Everything the screens render comes from a <template> in index.html,
// never from a string built in JavaScript: markup that lives in the document can be read by
// the accessibility checks in the suite, and there is no innerHTML anywhere to review.

export function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`dom: missing #${id}`);
  return element as T;
}

export function cloneScreen(id: string): DocumentFragment {
  const template = document.getElementById(id);
  if (!(template instanceof HTMLTemplateElement)) throw new Error(`dom: missing template #${id}`);
  return template.content.cloneNode(true) as DocumentFragment;
}

export function role<T extends HTMLElement>(root: ParentNode, name: string): T {
  const element = root.querySelector(`[data-role="${name}"]`);
  if (!element) throw new Error(`dom: missing [data-role="${name}"]`);
  return element as T;
}

export function setHidden(element: HTMLElement, hidden: boolean): void {
  element.hidden = hidden;
}

export function setText(element: HTMLElement, text: string): void {
  element.textContent = text;
}

/** Fill an <ol> with one <li> per item. Used for the six safety words. */
export function setList(list: HTMLElement, items: readonly string[]): void {
  list.replaceChildren(
    ...items.map((item) => {
      const li = document.createElement('li');
      li.textContent = item;
      return li;
    }),
  );
}

/** Shorten a 32 byte key to something two people can read to each other if they want to. */
export function shortHex(hex: string, groups = 4): string {
  return (hex.match(/.{1,4}/g) ?? []).slice(0, groups).join(' ');
}
