import {test} from 'node:test';
import assert from 'node:assert/strict';
import {webmasterUrl,matchesProperty,statusRows} from './yandex_webmaster_auth_inspector.mjs';

test('Prevent wrong domain and redirected Webmaster identity',()=>{
 const exact=webmasterUrl('potrebpravo.ru','sitemap');
 assert.equal(matchesProperty(exact,'potrebpravo.ru','sitemap'),true);
 assert.equal(matchesProperty(exact+'?foo=1','potrebpravo.ru','sitemap'),true);
 assert.equal(matchesProperty(exact,'semya-yurist.ru','sitemap'),false);
 assert.equal(matchesProperty(exact.replace('webmaster.yandex.ru','evil.example'),'potrebpravo.ru','sitemap'),false);
 assert.equal(matchesProperty(exact.replace('/sitemap/','/reindex/'),'potrebpravo.ru','sitemap'),false);
 assert.throws(()=>webmasterUrl('unrelated.example','sitemap'));
 assert.throws(()=>webmasterUrl('potrebpravo.ru','delete-site'));
});
test('Extract only selected domain statuses, avoid arbitrary dashboard text',()=>{
 const source=[
  'Переобход страниц', 'URL: https://potrebpravo.ru/ — В очереди',
  'Результат за время ожидания: нет',
  'ОК: Файлы sitemap обработаны',
  'Личные настройки пользователя'
 ];
 const rows=statusRows(source,'potrebpravo.ru');
 assert.equal(rows.some(s=>s.includes('В очереди')),true);
 assert.equal(rows.some(s=>s.includes('обработаны')),true);
 assert.equal(rows.some(s=>s.includes('Личные настройки')),false);
});
