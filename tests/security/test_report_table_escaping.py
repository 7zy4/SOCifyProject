"""report_table is the one place whose HTML the printable quick report trusts as markup, so it must escape everything."""

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from socify.autopsy_report_render import report_table

HOSTILE = ["<script>x</script>", '"><img src=x onerror=1>', "' onmouseover='1", "</td></tr></table><b>", "&lt;b&gt;", "‮<i>"]
text = st.one_of(st.sampled_from(HOSTILE), st.text(max_size=12))
scalar = st.one_of(st.none(), st.booleans(), st.integers(), text)
evidence = st.recursive(scalar, lambda inner: st.one_of(st.lists(inner, max_size=4), st.dictionaries(text, inner, max_size=4)), max_leaves=24)
TAGS = {"table", "thead", "tbody", "tr", "th", "td", "bdi", "span"}


@settings(max_examples=300, deadline=None)
@given(value=evidence, localize=st.booleans())
def test_every_key_and_value_reaches_the_table_as_text(value, localize):
    markup = report_table(value, localize=localize)
    # Only the table's own elements may appear; anything else would be stored text turned into markup.
    assert {tag.lower() for tag in re.findall(r"</?([A-Za-z][\w-]*)", markup)} <= TAGS
    assert not re.search(r"<[^>]*(onerror|onmouseover|script|<img)", markup, re.IGNORECASE)
    assert "<script>" not in markup and "<img" not in markup and "<b>" not in markup and "<i>" not in markup
