// Application authorization/CSRF controls; never substitute a WAF refusal.
const assert=require('node:assert/strict');
module.exports=async function({f,page,context,api,test,customer,invoice,invoiceRef,id}) {
  const read=()=>api('GET','thirdparties/'+customer);
  async function form() {
    await page.goto(f.origin+'/societe/card.php?socid='+customer+'&action=edit');
    return page.locator('form').filter({has:page.locator('input[name=action][value=update]')}).evaluate(element=>{
      const result={}; for(const [name,value] of new FormData(element)) if(typeof value==='string') result[name]=value;
      return result;
    });
  }
  await test('application CSRF rejects missing and invalid tokens; valid form commits',async()=>{
    const original=(await read()).name;
    let data=await form(); assert.ok(data.token); data.name='Missing CSRF '+id; delete data.token;
    const missing=await context.request.post(f.origin+'/societe/card.php',{form:data});
    assert.equal(missing.status(),403); assert.match(await missing.text(),/refused by CSRF protection/);
    assert.equal((await read()).name,original);
    data=await form(); data.name='Invalid CSRF '+id; data.token='invalid-'+id;
    const invalid=await context.request.post(f.origin+'/societe/card.php',{form:data});
    assert.equal(invalid.status(),200); assert.equal((await read()).name,original);
    data=await form(); data.name=original+' reviewed';
    const valid=await context.request.post(f.origin+'/societe/card.php',{form:data});
    assert.equal(valid.status(),200); assert.equal((await read()).name,data.name);
    return {missing_token_status:403,invalid_token_unchanged:true,valid_token_committed:true};
  });
  await test('reader can read customer but cannot edit or create customers',async()=>{
    const original=await read();
    const initial=await api('GET','thirdparties/'+customer,undefined,[403],f.reader_api_key);
    assert.match((await initial.json()).error.message,/access/i);
    await api('POST',`thirdparties/${customer}/representative/${f.reader_id}`);
    const visible=await api('GET','thirdparties/'+customer,undefined,[200],f.reader_api_key);
    assert.equal(visible.name,original.name);
    const unassigned=await api('POST','thirdparties',{name:'Unassigned customer '+id,client:1,code_client:'-1'});
    const boundary=await api('GET','thirdparties/'+unassigned,undefined,[403],f.reader_api_key);
    assert.match((await boundary.json()).error.message,/access/i);
    const update=await api('PUT','thirdparties/'+customer,{name:'Forbidden edit '+id},[403],f.reader_api_key);
    const updateError=(await update.json()).error; assert.equal(updateError.code,403); assert.match(updateError.message,/rights|Forbidden/i);
    const create=await api('POST','thirdparties',{name:'Forbidden creation '+id,client:1},[403],f.reader_api_key);
    const createError=(await create.json()).error; assert.equal(createError.code,403); assert.match(createError.message,/rights|Forbidden/i);
    assert.equal((await read()).name,original.name);
    const all=await api('GET','thirdparties?limit=100');
    assert.ok(!all.some(x=>x.name==='Forbidden creation '+id));
    return {read_allowed:true,unassigned_customer_denied:true,update_denied_by_application:true,creation_denied_by_application:true,unchanged:true};
  });
  await test('reader cannot access invoice or its document',async()=>{
    const denied=await api('GET','invoices/'+invoice,undefined,[403],f.reader_api_key);
    const invoiceError=(await denied.json()).error; assert.equal(invoiceError.code,403); assert.match(invoiceError.message,/rights|access|Forbidden/i);
    const doc=await api('GET','documents/download?modulepart=invoice&original_file='+encodeURIComponent(invoiceRef+'/'+invoiceRef+'.pdf'),undefined,[403],f.reader_api_key);
    const documentError=(await doc.json()).error; assert.equal(documentError.code,403); assert.match(documentError.message,/access|Forbidden/i);
    const owner=await api('GET','invoices/'+invoice); assert.equal(Number(owner.total_ht),250);
    return {invoice_denied_by_application:true,document_denied_by_application:true,administrator_access_retained:true};
  });
};
