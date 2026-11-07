<?php
// Test-only fixture data in the isolated PrestaShop container. No live payment.
$input = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
require '/var/www/html/config/config.inc.php';
if (!empty($input['report'])) {
    $customerId = (int) Customer::customerExists('customer@example.invalid', true);
    $orderId = (int) Db::getInstance()->getValue('SELECT id_order FROM '._DB_PREFIX_.'orders WHERE id_customer='.$customerId.' ORDER BY id_order DESC');
    if (!$orderId) { throw new Exception('No committed qualification order'); }
    $order = new Order($orderId);
    // Inspect committed rows rather than recalculating display prices in a CLI
    // context without a browser-selected currency/cart.
    $lines = Db::getInstance()->executeS('SELECT product_reference, product_quantity FROM '._DB_PREFIX_.'order_detail WHERE id_order='.$orderId);
    if (count($lines) !== 1) { throw new Exception('Unexpected order line count'); }
    $line = reset($lines);
    if ($line['product_reference'] !== 'OPENWAF-LAB' || (int)$line['product_quantity'] !== 2 ||
        abs((float)$order->total_products - 50) > 0.001 || $order->hasBeenPaid() ||
        (int)$order->getCurrentState() !== (int)Configuration::get('PS_OS_BANKWIRE')) {
        throw new Exception('Committed order state or totals differ from offline checkout');
    }
    echo json_encode(['order_id'=>$orderId,'quantity'=>2,'products_total'=>50,'unpaid'=>true,'bank_wire_state'=>true]);
    exit;
}
Configuration::updateValue('PS_MAIL_METHOD', 3); // Suppress external mail.
Configuration::updateValue('BANK_WIRE_OWNER', 'OpenWAF Lab');
Configuration::updateValue('BANK_WIRE_DETAILS', 'TEST ONLY - no bank account');
Configuration::updateValue('BANK_WIRE_ADDRESS', 'Example Street');
$module = Module::getInstanceByName('ps_wirepayment');
if (!$module || (!Module::isInstalled('ps_wirepayment') && !$module->install())) {
    throw new Exception('Offline payment module unavailable');
}
$module->enable();
$customerId = (int) Customer::customerExists('customer@example.invalid', true);
if (!$customerId) {
    $customer = new Customer();
    $customer->firstname = 'Qualification'; $customer->lastname = 'Customer';
    $customer->email = 'customer@example.invalid'; $customer->passwd = Tools::hash($input['password']);
    $customer->active = 1; $customer->id_default_group = 3;
    if (!$customer->add()) { throw new Exception('Customer creation failed'); }
    $customerId = (int) $customer->id;
    $address = new Address(); $address->id_customer = $customerId; $address->alias = 'Lab address';
    $address->firstname = 'Qualification'; $address->lastname = 'Customer';
    $address->address1 = '12 Example Street'; $address->city = 'Paris'; $address->postcode = '75001';
    $address->id_country = (int) Country::getByIso('FR'); $address->phone = '0100000000';
    if (!$address->add()) { throw new Exception('Address creation failed'); }
}
$productId = (int) Db::getInstance()->getValue("SELECT id_product FROM "._DB_PREFIX_."product WHERE reference='OPENWAF-LAB'");
if (!$productId) {
    $product = new Product();
    foreach (Language::getLanguages(false) as $language) {
        $product->name[(int)$language['id_lang']] = 'OpenWAF Qualification Product';
        $product->link_rewrite[(int)$language['id_lang']] = 'openwaf-qualification-product';
        $product->description[(int)$language['id_lang']] = '<p>Support &amp; maintenance.</p>';
    }
    $product->reference = 'OPENWAF-LAB'; $product->price = 25; $product->id_tax_rules_group = 0;
    $product->id_category_default = 2; $product->active = 1; $product->available_for_order = 1;
    $product->show_price = 1; $product->visibility = 'both'; $product->minimal_quantity = 1;
    if (!$product->add()) { throw new Exception('Product creation failed'); }
    $product->addToCategories([2]); $productId = (int) $product->id;
    StockAvailable::setQuantity($productId, 0, 100);
}
Search::indexation(false, $productId);
$link = Context::getContext()->link;
$routes = ['search'=>$link->getPageLink('search', null, null, ['s'=>'OpenWAF']),
    'login'=>$link->getPageLink('authentication'), 'addresses'=>$link->getPageLink('addresses'),
    'product'=>$link->getProductLink($productId), 'cart'=>$link->getPageLink('cart', null, null, ['action'=>'show']),
    'checkout'=>$link->getPageLink('order')];
echo json_encode(['version'=>_PS_VERSION_, 'product_id'=>$productId, 'customer_id'=>$customerId, 'routes'=>$routes]);
