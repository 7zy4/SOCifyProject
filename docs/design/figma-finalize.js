// Execute in the SOCify file with use_figma after the Starter tool quota resets.
// Load docs/design/figma-state.json into LEDGER before this script.
// The script is safe to retry: reactions replace existing values; specimen is built once.
await Promise.all(['Almarai', 'IBM Plex Sans'].flatMap(family => ['Regular', 'Bold'].map(style => figma.loadFontAsync({ family, style }))));
const page = await figma.getNodeByIdAsync(LEDGER.pages[1].id);
await figma.setCurrentPageAsync(page);
let reactions = 0;
for (const screen of LEDGER.wrappers) {
  const root = await figma.getNodeByIdAsync(screen.id);
  for (const source of root.findAllWithCriteria({ types: ['INSTANCE'] })) {
    if (!source.name.startsWith('to:')) continue;
    const route = source.name.slice(3);
    let destination;
    if (route === 'language') destination = LEDGER.wrappers.find(next => next.locale !== screen.locale && next.theme === screen.theme && next.route === screen.route && next.width === screen.width);
    else if (route === 'theme') destination = LEDGER.wrappers.find(next => next.locale === screen.locale && next.theme !== screen.theme && next.route === screen.route && next.width === screen.width);
    else destination = LEDGER.wrappers.find(next => next.locale === screen.locale && next.theme === screen.theme && next.route === route && next.width === screen.width) || LEDGER.wrappers.find(next => next.locale === screen.locale && next.theme === screen.theme && next.route === route && next.width === 1440);
    if (!destination || destination.id === screen.id) continue;
    await source.setReactionsAsync([{ trigger: { type: 'ON_CLICK' }, actions: [{ type: 'NODE', destinationId: destination.id, navigation: 'NAVIGATE', transition: null, preserveScrollPosition: false }] }]);
    reactions++;
  }
}
return { linkedReactions: reactions, screenCount: LEDGER.wrappers.length };
