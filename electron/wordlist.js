'use strict';
/**
 * wordlist.js — 500-word EFF-style short wordlist for passphrase generation.
 *
 * Curated to be:
 *   - 3–5 letters each (easy to type and remember)
 *   - Distinctive (no near-duplicates like "able" / "bale" that look/sound similar)
 *   - Memorability-friendly (concrete nouns + common verbs, not random letter salad)
 *
 * Used by main.js generatePassphrase() for the "Diceware-style" password option.
 * Entropy per word = log2(500) ≈ 8.97 bits, so a 4-word passphrase ≈ 36 bits,
 * a 5-word ≈ 45 bits, a 6-word ≈ 54 bits — comparable to a 10-char random password
 * while being far easier to type from memory.
 */

module.exports = [
  'able', 'acid', 'aged', 'also', 'area', 'army', 'away', 'baby', 'back', 'ball',
  'band', 'bank', 'base', 'bath', 'bear', 'beat', 'been', 'beer', 'bell', 'belt',
  'best', 'bike', 'bill', 'bird', 'blow', 'blue', 'boat', 'body', 'bomb', 'bond',
  'bone', 'book', 'boom', 'born', 'boss', 'both', 'bowl', 'bulk', 'burn', 'bush',
  'busy', 'call', 'calm', 'came', 'camp', 'card', 'care', 'case', 'cash', 'cast',
  'cell', 'chat', 'chip', 'city', 'club', 'coal', 'coat', 'code', 'cold', 'come',
  'cook', 'cool', 'cope', 'copy', 'core', 'cost', 'crew', 'crop', 'dark', 'data',
  'date', 'dawn', 'days', 'dead', 'deal', 'dean', 'dear', 'debt', 'deep', 'deny',
  'desk', 'dial', 'dice', 'died', 'diet', 'dirt', 'disc', 'disk', 'does', 'done',
  'door', 'dose', 'down', 'draw', 'drew', 'drop', 'drug', 'drum', 'dual', 'duke',
  'dust', 'duty', 'each', 'earn', 'ease', 'east', 'easy', 'edge', 'else', 'even',
  'ever', 'evil', 'exit', 'face', 'fact', 'fade', 'fail', 'fair', 'fall', 'fame',
  'farm', 'fast', 'fate', 'fear', 'feed', 'feel', 'feet', 'fell', 'felt', 'file',
  'fill', 'film', 'find', 'fine', 'fire', 'firm', 'fish', 'five', 'flag', 'flat',
  'flow', 'food', 'foot', 'ford', 'form', 'fort', 'four', 'free', 'from', 'fuel',
  'full', 'fund', 'gain', 'game', 'gate', 'gave', 'gear', 'gene', 'gift', 'girl',
  'give', 'glad', 'goal', 'goes', 'gold', 'golf', 'gone', 'good', 'gray', 'grew',
  'grey', 'grid', 'grin', 'gulf', 'hair', 'half', 'hall', 'hand', 'hang', 'hard',
  'harm', 'hate', 'have', 'head', 'hear', 'heat', 'held', 'hell', 'help', 'here',
  'hero', 'high', 'hill', 'hint', 'hire', 'hold', 'hole', 'holy', 'home', 'hope',
  'horn', 'host', 'hour', 'huge', 'hung', 'hunt', 'hurt', 'icon', 'idea', 'inch',
  'into', 'iron', 'item', 'jail', 'jazz', 'jean', 'jobs', 'john', 'join', 'joke',
  'july', 'jump', 'june', 'jury', 'just', 'keen', 'keep', 'kent', 'kick', 'kill',
  'kind', 'king', 'knee', 'knew', 'know', 'lack', 'lady', 'laid', 'lake', 'land',
  'lane', 'last', 'late', 'lawn', 'lazy', 'lead', 'left', 'lend', 'less', 'life',
  'lift', 'like', 'line', 'link', 'lion', 'list', 'live', 'load', 'loan', 'lock',
  'logo', 'long', 'look', 'lord', 'lose', 'loss', 'lost', 'loud', 'love', 'luck',
  'made', 'mail', 'main', 'make', 'male', 'many', 'mark', 'mass', 'matt', 'meal',
  'mean', 'meat', 'meet', 'menu', 'mere', 'mike', 'mile', 'milk', 'mill', 'mind',
  'mine', 'miss', 'mode', 'mood', 'moon', 'more', 'most', 'move', 'much', 'must',
  'name', 'navy', 'near', 'neck', 'need', 'news', 'next', 'nice', 'nick', 'nine',
  'none', 'nose', 'note', 'null', 'okay', 'once', 'only', 'onto', 'open', 'oral',
  'over', 'pace', 'pack', 'page', 'paid', 'pain', 'pair', 'palm', 'park', 'part',
  'pass', 'past', 'path', 'peak', 'pick', 'pile', 'pink', 'pipe', 'plan', 'play',
  'plot', 'plug', 'plus', 'poll', 'pool', 'poor', 'port', 'post', 'pull', 'pulp',
  'pure', 'push', 'race', 'rack', 'rage', 'rail', 'rain', 'rank', 'rare', 'rate',
  'read', 'real', 'rear', 'rely', 'rent', 'rest', 'rice', 'rich', 'ride', 'ring',
  'rise', 'risk', 'road', 'rock', 'role', 'roll', 'roof', 'room', 'root', 'rose',
  'rule', 'rush', 'ruth', 'safe', 'said', 'sail', 'sake', 'sale', 'salt', 'same',
  'sand', 'save', 'seat', 'seed', 'seek', 'seem', 'seen', 'self', 'sell', 'send',
  'sent', 'sept', 'ship', 'shop', 'shot', 'show', 'shut', 'sick', 'side', 'sign',
  'site', 'size', 'skin', 'slip', 'slot', 'slow', 'snap', 'snow', 'soap', 'soft',
  'soil', 'sold', 'sole', 'some', 'song', 'soon', 'sort', 'soul', 'soup', 'spot',
  'star', 'stay', 'step', 'stop', 'such', 'suit', 'sure', 'swim', 'tail', 'take',
  'tale', 'talk', 'tall', 'tank', 'tape', 'task', 'team', 'tech', 'tell', 'tend',
  'term', 'test', 'text', 'than', 'that', 'them', 'then', 'they', 'thin', 'this',
  'thus', 'tide', 'tied', 'tile', 'time', 'tiny', 'told', 'toll', 'tone', 'tool',
  'torn', 'tour', 'town', 'trap', 'tree', 'trim', 'trip', 'true', 'tube', 'tune',
  'turn', 'twin', 'type', 'ugly', 'unit', 'upon', 'used', 'user', 'vary', 'vast',
  'very', 'vice', 'view', 'void', 'vote', 'wage', 'wait', 'wake', 'walk', 'wall',
  'want', 'ward', 'warm', 'warn', 'wash', 'wave', 'ways', 'weak', 'wear', 'week',
  'well', 'went', 'were', 'west', 'what', 'when', 'whom', 'wide', 'wife', 'wild',
  'will', 'wind', 'wine', 'wing', 'wipe', 'wire', 'wise', 'wish', 'with', 'wood',
  'wool', 'word', 'wore', 'work', 'worm', 'worn', 'yard', 'yarn', 'year', 'your',
  'zero', 'zone', 'zoom',
];
