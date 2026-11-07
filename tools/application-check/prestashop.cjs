// Storefront transactions; bank-wire orders are synthetic and remain unpaid.
const assert = require('node:assert/strict');

module.exports = async function qualify({ f, http, page, test }) {
  for (const value of Object.values(f.routes)) assert.equal(new URL(value).origin, f.origin);
  await test('storefront and seeded product search', async () => {
    await page.goto(f.routes.search);
    assert.ok((await page.locator('body').innerText()).includes('OpenWAF Qualification Product'));
    return { product_id: f.product_id };
  });
  await test('storefront rejects wrong customer password without authenticating',async()=>{
    await page.goto(f.routes.login);
    await page.locator('#login-form input[name=email]').fill('customer@example.invalid');
    await page.locator('#login-form input[name=password]').fill('incorrect-qualification-password');
    await page.locator('#submit-login').click();await page.waitForLoadState('domcontentloaded');
    assert.match(await page.locator('body').innerText(),/authentication failed|invalid|incorrect/i);
    assert.equal(await page.locator('a.logout').count(),0);
    return {application_rejected:true,authenticated:false};
  });
  await test('customer password login and saved address', async () => {
    await page.goto(f.routes.login);
    await page.locator('#login-form input[name=email]').fill('customer@example.invalid');
    await page.locator('#login-form input[name=password]').fill(f.password);
    await page.locator('#submit-login').click();
    await page.waitForLoadState('domcontentloaded');
    assert.ok(await page.locator('a.logout, a[href*="mylogout"]').count());
    await page.goto(f.routes.addresses);
    assert.ok((await page.locator('body').innerText()).includes('12 Example Street'));
    return { authenticated: true, saved_address: true };
  });
  await test('add product to cart and change quantity', async () => {
    await page.goto(f.routes.product);
    const add = page.locator('[data-button-action="add-to-cart"]').first();
    await add.click();
    await page.locator('#blockcart-modal').waitFor({ state: 'visible' });
    await page.goto(f.routes.cart);
    const qty = page.locator('input.js-cart-line-product-quantity').first();
    await qty.fill('2'); await qty.press('Enter');
    await page.waitForTimeout(1000);
    await page.reload();
    assert.equal(await page.locator('input.js-cart-line-product-quantity').first().inputValue(), '2');
    assert.ok((await page.locator('body').innerText()).includes('OpenWAF Qualification Product'));
    return { quantity: 2, expected_products_total: 50 };
  });
  await test('cart removal persists and product can be readded before checkout',async()=>{
    await page.goto(f.routes.cart);
    await page.locator('a[data-link-action="delete-from-cart"]').first().click();await page.waitForTimeout(1000);await page.reload();
    assert.equal(await page.locator('input.js-cart-line-product-quantity').count(),0);
    await page.goto(f.routes.product);await page.locator('[data-button-action="add-to-cart"]').first().click();
    await page.locator('#blockcart-modal').waitFor({state:'visible'});await page.goto(f.routes.cart);
    const qty=page.locator('input.js-cart-line-product-quantity').first();await qty.fill('2');await qty.press('Enter');
    await page.waitForTimeout(1000);await page.reload();assert.equal(await page.locator('input.js-cart-line-product-quantity').first().inputValue(),'2');
    return {removed_persistently:true,readded_quantity:2};
  });
  await test('complete checkout with offline bank-wire payment', async () => {
    await page.goto(f.routes.checkout);
    const addresses = page.locator('button[name=confirm-addresses]');
    if (await addresses.isVisible()) { await addresses.click(); await page.waitForTimeout(500); }
    const shipping = page.locator('button[name=confirmDeliveryOption]');
    if (await shipping.isVisible()) { await shipping.click(); await page.waitForTimeout(500); }
    const payment = page.locator('input[data-module-name="ps_wirepayment"]');
    await payment.check();
    await page.locator('input[name="conditions_to_approve[terms-and-conditions]"]').check();
    const submit = page.locator('#payment-confirmation button[type=submit]');
    await submit.click();
    await page.waitForURL(/order-confirmation/, { timeout: 30000 });
    assert.ok((await page.locator('body').innerText()).match(/confirmed|confirmation/i));
    return { order_confirmation: true, live_payment: false };
  });
  await test('storefront search blocks injection and XSS', async () => {
    for (const payload of ["1 UNION SELECT NULL,NULL,NULL-- -", '<script>alert(1)</script>']) {
      const target=new URL(f.routes.search); target.searchParams.set('s',payload);
      const res = await http.get(target.toString());
      assert.equal(res.status(), 403);
    }
    return { attack_pairs: 2 };
  });
};
