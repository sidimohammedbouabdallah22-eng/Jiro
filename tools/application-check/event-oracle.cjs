// Full bounded history: silently checking only the first page loses evidence.
const assert=require('node:assert/strict');
module.exports=async function allEvents(admin) {
  const items=[],seen=new Set();let before=0,pages=0;
  while(true) {
    const page=await admin('events/search?limit=499'+(before?'&before='+before:''));pages++;
    assert.ok(Array.isArray(page.items) && page.items.length<=499);
    assert.equal(typeof page.has_more,'boolean');
    for(const item of page.items) {assert.equal(typeof item.id,'string');assert.ok(item.id && !seen.has(item.id),'duplicate event in paged history');seen.add(item.id);items.push(item);}
    assert.ok(items.length<=10000 && pages<=21,'history exceeds the bounded fixture oracle');
    if(!page.has_more)return {items,has_more:false,pages};
    assert.ok(page.items.length && Number.isSafeInteger(page.next_before) && page.next_before>0 && (!before || page.next_before<before),'invalid event cursor progression');
    before=page.next_before;
  }
};
