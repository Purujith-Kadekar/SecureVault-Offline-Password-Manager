/**
 * domainUtils.js — Shared base-domain normalization (ES module).
 *
 * Single source of truth for getBaseDomain() and domainMatches().
 * Imported by background.js (SW context). Content scripts (which can't
 * use ES modules in MV3) delegate via chrome.runtime.sendMessage or
 * use the urlMatcher.js Symbol-keyed namespace — but urlMatcher.js now
 * has its own copy of the PUBLIC_SUFFIXES_TWO_PART set (kept in sync
 * manually since content scripts are IIFEs).
 *
 * E13: The PUBLIC_SUFFIXES_TWO_PART set has been expanded from ~55 to
 * ~150 entries covering the most common two-part TLDs. The full Mozilla
 * Public Suffix List (PSL) has ~8,000 entries; this covers the vast
 * majority of practical use. For entries not in the list, the algorithm
 * falls back to simple last-two-part extraction, which is correct for
 * standard single-part TLDs (.com, .org, .net, etc.) but may return
 * slightly incorrect results for obscure two-part TLDs not in the set.
 * This tradeoff is acceptable for a password manager's domain matching.
 *
 * Rules:
 *   - Strip protocol, port, path, query, fragment, auth
 *   - Strip leading "www." (case-insensitive)
 *   - Detect common two-part TLDs and return last THREE parts;
 *     otherwise return last TWO parts.
 *   - Auth stripping (user:pass@) happens BEFORE port stripping
 *     to avoid splitting at the auth colon.
 */

const PUBLIC_SUFFIXES_TWO_PART = new Set([
  // United Kingdom
  'co.uk', 'ac.uk', 'gov.uk', 'org.uk', 'me.uk', 'net.uk', 'ltd.uk', 'plc.uk',
  'police.uk', 'mod.uk', 'nhs.uk', 'sch.uk', 'british-library.uk',
  // Japan
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp', 'ed.jp', 'gr.jp',
  // Australia
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
  // New Zealand
  'co.nz', 'net.nz', 'org.nz', 'ac.nz', 'govt.nz', 'geek.nz', 'iwi.nz', 'kiwi.nz',
  // India
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'ac.in', 'edu.in', 'res.in',
  // Korea
  'co.kr', 'or.kr', 'ne.kr', 'go.kr', 'ac.kr', 'hs.kr', 'ms.kr', 'sc.kr',
  // Brazil
  'com.br', 'org.br', 'net.br', 'gov.br', 'edu.br', 'mil.br', 'art.br', 'eco.br',
  'blog.br', 'flog.br', 'nom.br', 'vlog.br', 'wiki.br', 'adm.br', 'adv.br',
  'arq.br', 'ato.br', 'bio.br', 'cim.br', 'cng.br', 'cnt.br', 'ecn.br',
  'eng.br', 'esp.br', 'eti.br', 'fnd.br', 'fot.br', 'fst.br', 'g12.br',
  'geo.br', 'imb.br', 'ind.br', 'inf.br', 'jor.br', 'leg.br', 'lel.br',
  'med.br', 'mus.br', 'ntr.br', 'odo.br', 'ppg.br', 'pro.br', 'psc.br',
  'psi.br', 'qsl.br', 'rec.br', 'slg.br', 'srv.br', 'tmp.br', 'trd.br',
  'tur.br', 'tv.br', 'vet.br', 'zlg.br',
  // China
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn', 'mil.cn',
  // Taiwan
  'com.tw', 'org.tw', 'net.tw', 'gov.tw', 'edu.tw', 'idv.tw', 'game.tw',
  'eb.tw', 'club.tw',
  // Hong Kong
  'com.hk', 'org.hk', 'net.hk', 'gov.hk', 'edu.hk', 'idv.hk',
  // Singapore
  'com.sg', 'org.sg', 'net.sg', 'gov.sg', 'edu.sg', 'per.sg',
  // South Africa
  'co.za', 'org.za', 'net.za', 'gov.za', 'ac.za', 'web.za', 'agric.za',
  'alt.za', 'city.za', 'edu.za', 'law.za', 'mil.za', 'nom.za', 'school.za',
  'tel.za', 'tm.za',
  // Mexico
  'com.mx', 'org.mx', 'net.mx', 'gob.mx', 'edu.mx',
  // Russia
  'com.ru', 'net.ru', 'org.ru', 'gov.ru', 'edu.ru', 'pp.ru', 'int.ru',
  'mil.ru', 'test.ru',
  // France
  'asso.fr', 'nom.fr', 'com.fr', 'gouv.fr', 'prd.fr', 'presse.fr',
  'tm.fr', 'aeroport.fr', 'asso.fr', 'avocat.fr', 'cci.fr',
  'chambre-curiale.fr', 'chirurgien-dentiste.fr', 'expert-comptable.fr',
  'geometre-expert.fr', 'medecin.fr', 'notaires.fr', 'pharmacien.fr',
  'port.fr', 'veterinaire.fr',
  // Argentina
  'com.ar', 'org.ar', 'net.ar', 'gov.ar', 'edu.ar', 'int.ar', 'mil.ar',
  'tur.ar',
  // Germany
  'co.de',
  // Netherlands
  'co.nl', 'org.nl', 'net.nl',
  // Belgium
  'co.be', 'org.be', 'ac.be',
  // Sweden
  'org.se', 'pp.se', 'se.se',
  // Norway
  'co.no', 'org.no', 'net.no', 'priv.no',
  // Denmark
  'co.dk',
  // Finland
  'co.fi', 'org.fi', 'net.fi',
  // Spain
  'com.es', 'org.es', 'net.es', 'gob.es', 'edu.es', 'nom.es',
  // Italy
  'com.it', 'org.it', 'net.it', 'gov.it', 'edu.it',
  // Portugal
  'com.pt', 'org.pt', 'net.pt', 'gov.pt', 'edu.pt', 'int.pt',
  // Poland
  'com.pl', 'org.pl', 'net.pl', 'gov.pl', 'edu.pl', 'mil.pl', 'aid.pl',
  'agro.pl', 'atm.pl', 'auto.pl', 'biz.pl', 'chem.pl', 'cio.pl',
  'elka.pl', 'expo.pl', 'farm.pl', 'fm.pl', 'gmina.pl', 'info.pl',
  'mail.pl', 'media.pl', 'med.pl', 'mio.pl', 'ngo.pl', 'noc.pl',
  'nom.pl', 'pc.pl', 'powiat.pl', 'priv.pl', 'realestate.pl',
  'rel.pl', 'sex.pl', 'shop.pl', 'sklep.pl', 'sos.pl', 'sport.pl',
  'targi.pl', 'tele.pl', 'tm.pl', 'tour.pl', 'travel.pl', 'turystyka.pl',
  // Austria
  'co.at', 'org.at', 'net.at', 'gv.at', 'ac.at',
  // Switzerland
  'com.ch', 'org.ch', 'net.ch', 'gov.ch', 'edu.ch',
  // Ireland
  'com.ie', 'org.ie', 'net.ie', 'gov.ie', 'edu.ie',
  // Iceland
  'co.is', 'org.is', 'net.is', 'gov.is', 'edu.is',
  // Israel
  'co.il', 'org.il', 'net.il', 'gov.il', 'ac.il', 'k12.il', 'muni.il',
  // Turkey
  'com.tr', 'org.tr', 'net.tr', 'gov.tr', 'edu.tr', 'bel.tr', 'gen.tr',
  'info.tr', 'biz.tr', 'av.tr', 'dr.tr', 'pol.tr', 'tel.tr', 'tv.tr',
  'web.tr', 'name.tr', 'bank.tr',
  // Thailand
  'co.th', 'org.th', 'net.th', 'gov.th', 'ac.th', 'in.th', 'mil.th',
  // Indonesia
  'co.id', 'org.id', 'net.id', 'gov.id', 'ac.id', 'sch.id', 'web.id',
  'mil.id', 'biz.id',
  // Philippines
  'com.ph', 'org.ph', 'net.ph', 'gov.ph', 'edu.ph',
  // Malaysia
  'com.my', 'org.my', 'net.my', 'gov.my', 'edu.my', 'name.my',
  // Vietnam
  'com.vn', 'org.vn', 'net.vn', 'gov.vn', 'edu.vn', 'ac.vn', 'biz.vn',
  'info.vn', 'name.vn', 'pro.vn', 'health.vn',
  // Pakistan
  'com.pk', 'org.pk', 'net.pk', 'gov.pk', 'edu.pk', 'web.pk', 'fam.pk',
  'biz.pk',
  // Bangladesh
  'com.bd', 'org.bd', 'net.bd', 'gov.bd', 'edu.bd', 'ac.bd',
  // Sri Lanka
  'com.lk', 'org.lk', 'net.lk', 'gov.lk', 'edu.lk', 'sch.lk', 'ac.lk',
  // Nepal
  'com.np', 'org.np', 'net.np', 'gov.np', 'edu.np',
  // Cambodia
  'com.kh', 'org.kh', 'net.kh', 'gov.kh', 'edu.kh', 'per.kh',
  // Egypt
  'com.eg', 'org.eg', 'net.eg', 'gov.eg', 'edu.eg', 'sci.eg', 'name.eg',
  // Morocco
  'co.ma', 'org.ma', 'net.ma', 'gov.ma', 'ac.ma',
  // Nigeria
  'com.ng', 'org.ng', 'net.ng', 'gov.ng', 'edu.ng', 'sch.ng', 'name.ng',
  'mil.ng', 'mob.ng',
  // Kenya
  'co.ke', 'org.ke', 'net.ke', 'go.ke', 'ac.ke', 'ne.ke', 'sc.ke',
  // Tanzania
  'co.tz', 'org.tz', 'net.tz', 'go.tz', 'ac.tz', 'ne.tz', 'sc.tz',
  // Ghana
  'com.gh', 'org.gh', 'net.gh', 'gov.gh', 'edu.gh',
  // Colombia
  'com.co', 'org.co', 'net.co', 'gov.co', 'edu.co', 'mil.co', 'nom.co',
  // Peru
  'com.pe', 'org.pe', 'net.pe', 'gov.pe', 'edu.pe', 'nom.pe', 'mil.pe',
  // Chile
  'com.cl', 'org.cl', 'net.cl', 'gov.cl', 'edu.cl',
  // Venezuela
  'com.ve', 'org.ve', 'net.ve', 'gov.ve', 'edu.ve', 'co.ve', 'info.ve',
  'mil.ve', 'web.ve', 'nom.ve',
  // Ecuador
  'com.ec', 'org.ec', 'net.ec', 'gov.ec', 'edu.ec', 'fin.ec', 'med.ec',
  'info.ec', 'pro.ec',
  // Uruguay
  'com.uy', 'org.uy', 'net.uy', 'gub.uy', 'edu.uy',
  // Paraguay
  'com.py', 'org.py', 'net.py', 'gov.py', 'edu.py', 'mil.py',
  // Bolivia
  'com.bo', 'org.bo', 'net.bo', 'gov.bo', 'edu.bo', 'mil.bo', 'int.bo',
  // Cuba
  'com.cu', 'org.cu', 'net.cu', 'gov.cu', 'edu.cu',
  // Dominican Republic
  'com.do', 'org.do', 'net.do', 'gov.do', 'edu.do', 'sld.do', 'gob.do',
  // Costa Rica
  'co.cr', 'org.cr', 'net.cr', 'go.cr', 'ac.cr', 'ed.cr',
  // Guatemala
  'com.gt', 'org.gt', 'net.gt', 'gob.gt', 'edu.gt', 'mil.gt', 'ind.gt',
  // Panama
  'com.pa', 'org.pa', 'net.pa', 'gob.pa', 'edu.pa', 'ac.pa', 'sld.pa',
  // Honduras
  'com.hn', 'org.hn', 'net.hn', 'gob.hn', 'edu.hn',
  // El Salvador
  'com.sv', 'org.sv', 'edu.sv', 'gob.sv', 'red.sv',
  // Nicaragua
  'com.ni', 'org.ni', 'net.ni', 'gob.ni', 'edu.ni', 'nom.ni',
  // Jamaica
  'com.jm', 'org.jm', 'net.jm', 'gov.jm', 'edu.jm',
  // Trinidad & Tobago
  'com.tt', 'org.tt', 'net.tt', 'gov.tt', 'edu.tt', 'info.tt', 'co.tt',
  'biz.tt', 'name.tt', 'pro.tt',
  // Barbados
  'com.bb', 'org.bb', 'net.bb', 'gov.bb', 'edu.bb',
  // Bahamas
  'com.bs', 'org.bs', 'net.bs', 'gov.bs', 'edu.bs',
  // Bermuda
  'com.bm', 'org.bm', 'net.bm', 'gov.bm', 'edu.bm',
  // Cayman Islands
  'com.ky', 'org.ky', 'net.ky', 'gov.ky', 'edu.ky',
  // Greenland
  'com.gl', 'org.gl', 'net.gl', 'edu.gl',
  // Faroe Islands
  'com.fo', 'org.fo', 'net.fo',
  // St. Vincent & Grenadines
  'com.vc', 'org.vc', 'net.vc', 'edu.vc',
  // Dominica
  'com.dm', 'org.dm', 'net.dm', 'edu.dm',
  // Grenada
  'com.gd', 'org.gd', 'net.gd', 'edu.gd',
  // Fiji
  'com.fj', 'org.fj', 'net.fj', 'gov.fj', 'edu.fj', 'name.fj', 'biz.fj',
  // Papua New Guinea
  'com.pg', 'net.pg', 'org.pg', 'gov.pg', 'edu.pg',
  // Samoa
  'com.ws', 'org.ws', 'net.ws', 'gov.ws', 'edu.ws',
  // Tonga
  'com.to', 'org.to', 'net.to', 'gov.to', 'edu.to',
  // Vanuatu
  'com.vu', 'org.vu', 'net.vu', 'edu.vu',
  // Solomon Islands
  'com.sb', 'org.sb', 'net.sb', 'edu.sb',
  // Micronesia
  'com.fm', 'org.fm', 'net.fm', 'edu.fm',
  // Palau
  'com.pw', 'org.pw', 'net.pw', 'edu.pw',
  // Marshall Islands
  'com.mh', 'org.mh', 'net.mh', 'edu.mh',
  // Saudi Arabia
  'com.sa', 'org.sa', 'net.sa', 'gov.sa', 'edu.sa', 'med.sa', 'pub.sa',
  'sch.sa',
  // UAE
  'co.ae', 'org.ae', 'net.ae', 'gov.ae', 'ac.ae', 'sch.ae', 'mil.ae',
  'pro.ae', 'name.ae',
  // Qatar
  'com.qa', 'org.qa', 'net.qa', 'gov.qa', 'edu.qa', 'mil.qa', 'name.qa',
  // Bahrain
  'com.bh', 'org.bh', 'net.bh', 'gov.bh', 'edu.bh',
  // Kuwait
  'com.kw', 'org.kw', 'net.kw', 'gov.kw', 'edu.kw',
  // Oman
  'com.om', 'org.om', 'net.om', 'gov.om', 'edu.om', 'med.om',
  // Jordan
  'com.jo', 'org.jo', 'net.jo', 'gov.jo', 'edu.jo', 'sch.jo', 'mil.jo',
  // Lebanon
  'com.lb', 'org.lb', 'net.lb', 'gov.lb', 'edu.lb',
  // Iraq
  'com.iq', 'org.iq', 'net.iq', 'gov.iq', 'edu.iq',
  // Iran
  'co.ir', 'org.ir', 'net.ir', 'gov.ir', 'ac.ir', 'sch.ir',
  // Libya
  'com.ly', 'org.ly', 'net.ly', 'gov.ly', 'edu.ly', 'med.ly',
  // Sudan
  'com.sd', 'org.sd', 'net.sd', 'gov.sd', 'edu.sd',
  // Tunisia
  'com.tn', 'org.tn', 'net.tn', 'gov.tn', 'edu.tn', 'ind.tn', 'fin.tn',
  // Algeria
  'com.dz', 'org.dz', 'net.dz', 'gov.dz', 'edu.dz', 'art.dz', 'ass.dz',
  // Cameroon
  'com.cm', 'org.cm', 'net.cm', 'gov.cm', 'edu.cm',
  // Senegal
  'com.sn', 'org.sn', 'net.sn', 'gov.sn', 'edu.sn',
  // Ivory Coast
  'com.ci', 'org.ci', 'net.ci', 'gov.ci', 'edu.ci', 'or.ci', 'co.ci',
  // Mozambique
  'co.mz', 'org.mz', 'net.mz', 'gov.mz', 'edu.mz',
  // Madagascar
  'com.mg', 'org.mg', 'net.mg', 'gov.mg', 'edu.mg',
  // Mauritius
  'com.mu', 'org.mu', 'net.mu', 'gov.mu', 'edu.mu', 'ac.mu', 'co.mu',
  // Réunion
  'com.re', 'org.re', 'net.re',
  // Guadeloupe / Martinique / French territories
  'com.gp', 'org.gp', 'net.gp', 'edu.gp',
  'com.mq', 'org.mq', 'net.mq', 'edu.mq',
  'com.gf', 'org.gf', 'net.gf',
  'com.nc', 'org.nc', 'net.nc',
  'com.pf', 'org.pf', 'edu.pf',
  'com.wf', 'org.wf', 'net.wf',
  // Mayotte
  'com.yt', 'org.yt', 'net.yt',
  // Saint Pierre and Miquelon
  'com.pm', 'org.pm', 'net.pm',
  // European ccTLDs
  'co.gg', 'org.gg', 'net.gg', 'edu.gg',
  'co.je', 'org.je', 'net.je', 'edu.je',
  'co.im', 'org.im', 'net.im', 'ac.im',
  'co.uk.com', 'org.uk.com',
  // Special / vanity
  'co.com', 'org.com',
  // Romania
  'com.ro', 'org.ro', 'net.ro', 'gov.ro', 'edu.ro', 'store.ro', 'info.ro',
  'tm.ro', 'nt.ro', 'nom.ro', 'rec.ro', 'arts.ro', 'firm.ro',
  // Bulgaria
  'com.bg', 'org.bg', 'net.bg', 'gov.bg', 'edu.bg',
  // Croatia
  'com.hr', 'org.hr', 'net.hr', 'gov.hr', 'edu.hr',
  // Serbia
  'co.rs', 'org.rs', 'net.rs', 'gov.rs', 'edu.rs', 'ac.rs',
  // Slovenia
  'com.si', 'org.si', 'net.si', 'gov.si', 'edu.si',
  // Slovakia
  'com.sk', 'org.sk', 'net.sk', 'gov.sk', 'edu.sk',
  // Czech Republic
  'co.cz', 'org.cz', 'net.cz', 'gov.cz',
  // Hungary
  'co.hu', 'org.hu', 'net.hu', 'gov.hu', 'edu.hu', 'info.hu', 'biz.hu',
  'name.hu', 'film.hu', 'sport.hu', 'hotel.hu', 'press.hu', 'tm.hu',
  // Lithuania
  'com.lt', 'org.lt', 'net.lt', 'gov.lt', 'edu.lt',
  // Latvia
  'com.lv', 'org.lv', 'net.lv', 'gov.lv', 'edu.lv',
  // Estonia
  'com.ee', 'org.ee', 'net.ee', 'gov.ee', 'edu.ee',
  // Ukraine
  'com.ua', 'org.ua', 'net.ua', 'gov.ua', 'edu.ua', 'co.ua',
  // Moldova
  'com.md', 'org.md', 'net.md', 'gov.md',
  // Georgia
  'com.ge', 'org.ge', 'net.ge', 'gov.ge', 'edu.ge',
  // Armenia
  'com.am', 'org.am', 'net.am',
  // Azerbaijan
  'com.az', 'org.az', 'net.az', 'gov.az', 'edu.az',
  // Uzbekistan
  'com.uz', 'org.uz', 'net.uz', 'gov.uz', 'edu.uz',
  // Kazakhstan
  'com.kz', 'org.kz', 'net.kz', 'gov.kz', 'edu.kz',
  // Kyrgyzstan
  'com.kg', 'org.kg', 'net.kg', 'gov.kg', 'edu.kg',
  // Tajikistan
  'com.tj', 'org.tj', 'net.tj', 'gov.tj', 'edu.tj',
  // Mongolia
  'com.mn', 'org.mn', 'net.mn', 'gov.mn', 'edu.mn',
  // Laos
  'com.la', 'org.la', 'net.la', 'gov.la', 'edu.la', 'info.la',
  // Myanmar
  'com.mm', 'org.mm', 'net.mm', 'gov.mm', 'edu.mm',
  // Maldives
  'com.mv', 'org.mv', 'net.mv', 'gov.mv', 'edu.mv',
  // Brunei
  'com.bn', 'org.bn', 'net.bn', 'edu.bn',
  // Timor-Leste
  'com.tl', 'org.tl', 'net.tl', 'gov.tl', 'edu.tl',
  // Luxembourg
  'com.lu', 'org.lu', 'net.lu',
  // Malta
  'org.mt', 'net.mt', 'gov.mt', 'edu.mt',
  // Cyprus
  'com.cy', 'org.cy', 'net.cy', 'gov.cy', 'edu.cy', 'ac.cy', 'biz.cy',
  // Gibraltar
  'com.gi', 'org.gi', 'net.gi', 'gov.gi', 'edu.gi',
  // Monaco
  'com.mc', 'org.mc', 'net.mc',
  // Andorra
  'com.ad', 'org.ad', 'net.ad',
  // San Marino
  'com.sm', 'org.sm', 'net.sm',
  // Liechtenstein
  'com.li', 'org.li', 'net.li',
  // Vatican
  'com.va', 'org.va', 'net.va',
  // Dominican Republic alternate
  'gob.do', 'sld.do',
  // United States — no two-part TLDs under .us, but some third-level:
  'co.us', 'org.us', 'net.us', 'gov.us', 'edu.us', 'k12.us', 'cc.us',
  'lib.us', 'state.us', 'dni.us', 'fed.us',
  // Canada
  'ab.ca', 'bc.ca', 'mb.ca', 'nb.ca', 'nf.ca', 'nl.ca', 'ns.ca', 'nt.ca',
  'nu.ca', 'on.ca', 'pe.ca', 'qc.ca', 'sk.ca', 'yk.ca',
  'co.ca', 'org.ca', 'net.ca', 'gc.ca', 'edu.ca',
  // Japan geographic
  'metro.jp', 'city.jp', 'pref.jp', 'town.jp', 'vill.jp',
  // UK geographic
  'city.uk', 'town.uk',
  // Special-use
  'co.ac', 'org.ac', 'net.ac', 'gov.ac', 'edu.ac'
]);

/**
 * Extract the base (registrable) domain from a URL string.
 * E13: Falls back to simple last-two-part extraction for TLDs not in the
 * expanded set. The full Mozilla PSL has ~8,000 entries; this covers the
 * most common ~150.
 * @param {string} url — any URL-like string (full URL, hostname, etc.)
 * @returns {string} — base domain (e.g. "example.co.uk") or ''
 */
export function getBaseDomain(url) {
  if (!url) return '';
  let s = String(url).trim().toLowerCase();

  // Strip protocol
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');

  // Strip everything after first /, ?, #
  const stop = s.search(/[\/?#]/);
  if (stop >= 0) s = s.slice(0, stop);

  // Strip auth (user:pass@) — MUST be done BEFORE stripping port,
  // because URLs like "user:pass@host:8080" have the auth colon BEFORE
  // the port colon.
  const at = s.indexOf('@');
  if (at >= 0) s = s.slice(at + 1);

  // Strip port
  const colon = s.indexOf(':');
  if (colon >= 0) s = s.slice(0, colon);

  // Strip leading "www."
  if (s.startsWith('www.')) s = s.slice(4);

  // Split and filter empties
  const parts = s.split('.').filter(p => p.length > 0);
  if (parts.length < 2) return s;

  // Two-part TLD detection (e.g. co.uk, com.au)
  // E13: Expanded set covers ~150 common two-part TLDs. For TLDs not in
  // the set, we fall back to simple last-two-part extraction, which is
  // correct for the vast majority of standard single-part TLDs (.com,
  // .org, .net, etc.).
  if (parts.length >= 3) {
    const lastTwo = parts.slice(-2).join('.');
    if (PUBLIC_SUFFIXES_TWO_PART.has(lastTwo)) {
      return parts.slice(-3).join('.');
    }
  }

  return parts.slice(-2).join('.');
}

/**
 * Check whether two URLs share the same base domain.
 * @param {string} urlA
 * @param {string} urlB
 * @returns {boolean}
 */
export function domainMatches(urlA, urlB) {
  const a = getBaseDomain(urlA);
  const b = getBaseDomain(urlB);
  if (!a || !b) return false;
  return a === b;
}

// Also export the suffix set so urlMatcher.js can reference it
// (content scripts can't import ES modules, but the set is kept
// in sync manually — urlMatcher.js has its own copy).
export { PUBLIC_SUFFIXES_TWO_PART };
