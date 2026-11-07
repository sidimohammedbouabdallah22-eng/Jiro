// Native ERP workflows against the pinned, isolated product; no application mocks.
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');

module.exports=async function({f,page,context,api,test,customer,id}) {
  await test('contact creation persists Unicode fields and reader cannot create contacts',async()=>{
    const name='O’Reilly — الجزائر '+id;
    const contact=await api('POST','contacts',{socid:Number(customer),lastname:name,firstname:'Capacity',email:'contact-'+id+'@example.invalid'});
    assert.ok(Number(contact)>0);
    const stored=await api('GET','contacts/'+contact);assert.equal(stored.lastname,name);assert.equal(Number(stored.socid),Number(customer));
    const denied=await api('POST','contacts',{socid:Number(customer),lastname:'Forbidden '+id},[403],f.reader_api_key);
    assert.match((await denied.json()).error.message,/permission|rights|Forbidden/i);
    return {contact_id:Number(contact),persisted:true,reader_denied_by_application:true};
  });
  await test('sales order lines and validation persist correct totals',async()=>{
    const order=await api('POST','orders',{socid:Number(customer),date:Math.floor(Date.now()/1000)});
    assert.ok(Number(order)>0);
    await api('POST',`orders/${order}/lines`,{desc:'Managed service — خدمة',qty:2,subprice:125,tva_tx:0,product_type:1});
    await api('POST',`orders/${order}/validate`,{idwarehouse:0,notrigger:0});
    const stored=await api('GET','orders/'+order);assert.equal(Number(stored.total_ht),250);assert.equal(Number(stored.statut),1);assert.equal(stored.lines.length,1);
    const denied=await api('GET','orders/'+order,undefined,[403],f.reader_api_key);
    assert.match((await denied.json()).error.message,/permission|rights|access|Forbidden/i);
    return {order_id:Number(order),total_ht:250,validated:true,reader_denied_by_application:true};
  });
  await test('native CSV multipart import simulates without commit then imports exact customer',async()=>{
    const name='CSV O’Reilly — الجزائر '+id;
    const email='csv-'+id+'@example.invalid';
    const csv=Buffer.from('name;status;client;supplier;code;email\n'+[name,'1','1','0','auto',email].map(s=>'"'+s.replaceAll('"','""')+'"').join(';')+'\n');
    const filename='native-'+id+'.csv';
    const base=f.origin+'/imports/import.php?datatoimport=societe_1&format=csv&separator=%3B&excludefirstline=2';
    await page.goto(base+'&step=2');
    await page.locator('input[type=file][name=userfile]').setInputFiles({name:filename,mimeType:'text/csv',buffer:csv});
    await page.locator('[name=sendit]').click();
    await page.waitForLoadState('domcontentloaded');
    const href=await page.locator('a[href*="step=3"][href*="'+filename+'"]').first().getAttribute('href');
    assert.ok(href,'uploaded native CSV absent');
    await page.goto(new URL(href,page.url()).toString());
    await page.waitForLoadState('networkidle');
    const token=await page.locator('input[name=token]').first().inputValue();
    const mapping=await context.request.post(base+'&step=3&action=saveselectorder&token='+encodeURIComponent(token),{form:{selectorder:'0,s.nom,s.status,s.client,s.fournisseur,s.code_client,s.email'}});
    assert.equal(mapping.status(),200);assert.deepEqual(await mapping.json(),{});
    await page.reload();
    const simulation=await page.locator('a[href*="step=4"][href*="filetoimport="]').first().getAttribute('href');
    assert.ok(simulation);await page.goto(new URL(simulation,page.url()).toString());
    await page.locator('form').filter({has:page.locator('input[name=action][value=launchsimu]')}).locator('input[type=submit]').click();
    await page.waitForLoadState('domcontentloaded');
    // The wizard's preview must not have inserted the row yet.
    let all=await api('GET','thirdparties?limit=1000');assert.equal(all.filter(x=>x.email===email).length,0);
    const commits=page.locator('a[href*="step=5"][href*="importid="]');
    assert.ok(await commits.count(),'native simulation refused: '+(await page.locator('body').innerText()).slice(-2000));
    const commit=await commits.first().getAttribute('href');
    assert.ok(commit,'native simulation did not offer commit');
    await page.goto(new URL(commit,page.url()).toString());
    all=await api('GET','thirdparties?limit=1000');const imported=all.filter(x=>x.email===email);assert.equal(imported.length,1);
    const stored=await api('GET','thirdparties/'+imported[0].id);assert.equal(stored.name,name);assert.equal(Number(stored.client),1);
    assert.ok(stored.code_client && stored.code_client!=='auto');
    return {customer_id:Number(imported[0].id),simulation_did_not_commit:true,committed_once:true,unicode_preserved:true,bytes:csv.length,sha256:createHash('sha256').update(csv).digest('hex')};
  });
  let uploadForm;
  await test('native customer multipart attachment round trips exact bytes',async()=>{
    const content=Buffer.from(('customer,description\n'+id+',Support — خدمة\n').repeat(2048));
    const filename='multipart-'+id+'.csv';
    await page.goto(f.origin+'/societe/document.php?socid='+customer);
    const form=page.locator('form').filter({has:page.locator('input[type=file]')}).first();
    uploadForm=await form.evaluate(element=>{const data={};for(const [k,v] of new FormData(element))if(typeof v==='string')data[k]=v;return {action:element.action,data};});
    const input=form.locator('input[type=file]').first();const field=await input.getAttribute('name');
    // Current Dolibarr hides its legacy submit button behind the AJAX uploader.
    // Exercise the native multipart endpoint with the actual form fields/token.
    const uploaded=await context.request.post(uploadForm.action,{multipart:{...uploadForm.data,sendit:'Upload',[field]:{name:filename,mimeType:'text/csv',buffer:content}}});
    assert.equal(uploaded.status(),200);await page.reload();
    const href=await page.locator('a[href*="document.php"][href*="'+filename+'"]').first().getAttribute('href');assert.ok(href);
    const response=await context.request.get(new URL(href,page.url()).toString());assert.equal(response.status(),200);assert.deepEqual(await response.body(),content);
    uploadForm.field=field;
    return {bytes:content.length,sha256:createHash('sha256').update(content).digest('hex'),native_multipart:true,exact_download:true};
  });
  await test('native multipart controls retain XSS and body size refusal',async()=>{
    const data={...uploadForm.data,sendit:'Send',payload:'<script>alert(1)</script>'};
    const attack=await context.request.post(uploadForm.action,{multipart:{...data,[uploadForm.field]:{name:'paired-'+id+'.csv',mimeType:'text/csv',buffer:Buffer.from('safe,data\n1,2\n')}}});
    assert.equal(attack.status(),403);
    delete data.payload;
    const large=await context.request.post(uploadForm.action,{multipart:{...data,[uploadForm.field]:{name:'large-'+id+'.csv',mimeType:'text/csv',buffer:Buffer.alloc(1048577,97)}}});
    assert.equal(large.status(),413);
    return {paired_xss_status:403,oversized_multipart_status:413};
  });
};
