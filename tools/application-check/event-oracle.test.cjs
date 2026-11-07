const test=require('node:test');const assert=require('node:assert/strict');const allEvents=require('./event-oracle.cjs');
test('reads every page and sends the exact cursor',async()=>{
  const paths=[];const pages=[{items:[{id:'a'},{id:'b'}],has_more:true,next_before:10},{items:[{id:'c'}],has_more:false}];
  const result=await allEvents(async path=>{paths.push(path);return pages.shift();});
  assert.deepEqual(result.items.map(x=>x.id),['a','b','c']);assert.equal(result.pages,2);assert.equal(paths[1],'events/search?limit=499&before=10');
});
test('duplicate IDs across pages fail rather than hiding a race',async()=>{
  let n=0;await assert.rejects(()=>allEvents(async()=>++n===1?{items:[{id:'a'}],has_more:true,next_before:10}:{items:[{id:'a'}],has_more:false}),/duplicate event/);
});
test('nondecreasing cursor fails instead of looping',async()=>{
  let n=0;await assert.rejects(()=>allEvents(async()=>({items:[{id:String(++n)}],has_more:true,next_before:10})),/cursor/);
});
test('history quota fails without truncating to a successful result',async()=>{
  let n=0;await assert.rejects(()=>allEvents(async()=>{const first=n++*499;return {items:Array.from({length:499},(_,i)=>({id:String(first+i)})),has_more:true,next_before:50000-first};}),/bounded fixture oracle/);assert.equal(n,21);
});
