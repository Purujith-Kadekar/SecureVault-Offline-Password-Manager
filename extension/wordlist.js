/**
 * wordlist.js — EFF-style passphrase wordlist (ES module).
 *
 * E10: Extracted from background.js for modular decomposition.
 * ~500 short, memorable words curated for passphrase generation.
 * The original inline string was ~200 lines in background.js.
 */

const WORDLIST = (
  'abandon ability above absent absorb abstract absurd abuse access accident account ' +
  'achieve acid acoustic acquire across action actor acute adapt address adjust admire ' +
  'admit adult advance advice aerial afford afraid again age agent agree ahead air ' +
  'airport aisle alarm album alert alien align all alley allow almost alone alpha ' +
  'already alter always amateur amazing among amount ample analog anchor ancient anger ' +
  'angle angry animal ankle annual answer antenna antique anxious any apart apex apple ' +
  'approve arch arctic area arena argue arm armed armor army around arrange arrest ' +
  'arrive arrow art artefact artist artwork ask aspect assault asset assist assume ' +
  'asthma athlete atom attack attend attitude attract auction audit august aunt author ' +
  'auto autumn average avocado avoid awake aware away awesome awful awkward axis bacon ' +
  'badge bag balance balcony ball bamboo banner bar barely bargain barrel base basic ' +
  'basket batch battle beach bean beauty because become beef before begin behave behind ' +
  'believe bell belt below bench benefit best betray better between beyond bicycle bid ' +
  'bike bind biology bird birth bitter black blade blame blanket blast bleak bless ' +
  'blind blood blossom blue blur blush board boat body boil bomb bone bonus book boost ' +
  'border boring borrow boss bottom bounce box boy bracket brain brand brass brave ' +
  'bread breeze brick bridge brief bright bring brisk broccoli broken bronze broom ' +
  'brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle ' +
  'bunker burden burger burst bus business busy butter buyer cabbage cabin cable ' +
  'cactus caddy cage cake call calm camera camp can canal cancel candy cannon canoe ' +
  'canvas canyon capable capital captain car carbon card cargo carpet carry cart ' +
  'case cash casino castle casual cat catalog catch category cattle caught cause ' +
  'caution cave ceiling celery cement census century cereal certain chair chalk champion ' +
  'change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken ' +
  'chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle ' +
  'citizen city civil claim clap clarify claw clay clean clerk clever click client ' +
  'cliff climb clinic clip clock clog close cloth cloud clown club clump cluster ' +
  'clutch coach coast coconut code coffee coil coin collect color column combine come ' +
  'comfort comic common company concert conduct confirm congress connect consider ' +
  'control convince cook cool copper copy coral core corn correct cost cotton couch ' +
  'country couple course cousin cover coyote craft cradle cram crane crash crater ' +
  'crazy cream credit creek crew cricket crime crisp critic crop cross crouch crowd ' +
  'crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard ' +
  'curious current curtain curve cushion custom cute cycle dad damage damp dance ' +
  'danger daring dash daughter dawn day deal debate debris decade decay december ' +
  'decide decline decorate decrease deep deer defense define defy degree delay deliver ' +
  'demand demise deny dentist depart depend deposit depth deputy derive descend ' +
  'describe desert design desk despair destroy detail detect develop device devote ' +
  'diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner ' +
  'dinosaur direct dirt disagree discover disease dish dismiss disorder display ' +
  'distance divert divide divorce dizzy doctor document dog doll dolphin domain donate ' +
  'donkey donor door dose double dove draft dragon drama drastic draw dream dress ' +
  'drift drill drink drip drive drop drum dry duck dung duo duration dust duty ' +
  'dwarf dynamic eager eagle early earn earth easily east easy echo ecology economy ' +
  'edge edit educate effort egg eight either elbow elder elect electron elegant ' +
  'element elephant elevator elite else embark embody embrace emerge emotion employ ' +
  'empower empty enable enact end endless endorse enemy energy enforce engage engine ' +
  'enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope ' +
  'episode equal equip era erase erode erosion error erupt escape essay essence ' +
  'estate eternal ethics evidence evil evoke evolve exact example excess exchange ' +
  'excite exclude excuse execute exercise exhaust exhibit exile exist exit exotic ' +
  'expand expect expire explain expose extend extra extreme eye fabric face faculty ' +
  'fade faint faith fall false fame family famous fan fancy fantasy farm fashion ' +
  'fat fatal father fatigue fault favorite feature february federal fee feed feel ' +
  'female fence festival fetch fever few fiber fiction field figure file filter ' +
  'finance final find fine finger finish fire firm first fish fitting fitness five ' +
  'flag flame flash flat flavor flee flight flip float flock floor flower fluid ' +
  'flush fly foam focus fog foil fold follow food foot force forest forget fork ' +
  'forum forward fossil foster found fox fragile frame frequent fresh friend ' +
  'fringe frog front frost frown frozen fruit fuel fun funny furnace fury future ' +
  'gadget gain galaxy gallery game garage garbage garden garlic garment gas gate ' +
  'gather gauge gaze gear genius genre gentle genuine gesture ghost giant gift giggle ' +
  'ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory ' +
  'glove glow glue go goal goat gold golden goose gorilla gospel gossip govern gown ' +
  'grab grace grain grand grant grape graph grasp grass gravity great green grid ' +
  'grief grit grocery groove gross ground group grove grow grumble grunt guard guess ' +
  'guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor harsh ' +
  'harvest hatch have hawk hazard head health heart heavy hedge heel height help ' +
  'helmet hero hidden high hill hint hire history hobby hockey hold hole holiday ' +
  'hollow home honey honor hood hope horn horror horse hospital host hotel hour hover ' +
  'huge human humble humor hundred hungry hunt hurdle hurl hurry hurt husband hybrid ' +
  'ice icon idea ideal identify idle idol ignore illegal illness image imitate immense ' +
  'immune impact impose improve impulse inch include income increase index indicate ' +
  'indoor industry infant inflict inform inhale inherit initial inject injury inmate ' +
  'inner innocent input inquiry insane insect inside inspire install intact interest ' +
  'into invest invite involve iron island isolate issue item ivory jacket jaguar jar ' +
  'jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle ' +
  'junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss ' +
  'kit kitchen kite kitten knee knife knight knot know knowledge lab label labor ' +
  'ladder lady lake lamp land language lap large laser last late latent later laugh ' +
  'launch lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg ' +
  'legal legend leisure lemon lend length lens leopard lesson letter level liberty ' +  // v10.9 FIX: removed duplicate 'ladder' (was listed twice, reducing passphrase entropy)
  'liberty library license life lift light like limb limit link lion liquid list ' +
  'little live lizard load lobster local lock logic lonely long loop lottery loud ' +
  'lounge love loyal lucky lumber lunar lunch luxury lyric machine mad magic magnet ' +
  'maid mail main major make mammal man manage mandate mango mansion manual maple ' +
  'marble march margin marine market marriage mask mass master match material math ' +
  'matrix matter maximum maze meadow mean measure meat media melody melon memo memory ' +
  'mention menu mercy merge merit merry mesh message metal method middle midnight ' +
  'million mimic mind mince mine minor mint minute mirror miss mission mist mix ' +
  'mobile model modify mom moment money monitor month moon moral more morning mother ' +
  'motion motor mountain mouse move movie much muffin mule muscle museum mushroom ' +
  'music must mutual myself mystery myth name napkin narrow nasty nation nature near ' +
  'neat necessary neck need needle neighbor nephew nerve nest network news next nice ' +
  'night niche nine nipple noble noise noodle normal north nose notable note nothing ' +
  'notice novel now nuclear number nurse nut oak obey object oblige obscure observe ' +
  'obtain obvious occur ocean october odor off offer office often oil okay old olive ' +
  'olympic omit once onion online only onset open opera opinion oppose option orange ' +
  'orbit orchard order organic orient original orphan other ostrich otter outer ' +
  'output outside oval oven over own owner oxygen oyster ozone pact paddle page pair ' +
  'palace palm panda panel panic panther paper parade parent park parrot parse party ' +
  'pass patch path patient patrol pattern pause pave payment peace peanut pear ' +
  'peasant pelican pen penalty pencil people pepper percent perfect perform perhaps ' +
  'period permit person pet phone photo phrase physical piano picnic picture piece ' +
  'pig pigeon pilot pink pioneer pipe pitch pizza place planet plastic plate play ' +
  'pleasure plot plug plunge poem poet point polar pole police pond pony pool popular ' +
  'portion position possible post potato pottery poverty powder power practice praise ' +
  'predict prefer prepare present pretty prevent price pride primary print priority ' +
  'prison private prize problem process produce profit program project promote proof ' +
  'proper prosper protect proud provide public pudding pull pulp pulse pumpkin punch ' +
  'pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum ' +
  'quarter queen quick quiz quote rabbit raccoon race rack radar radio rail rain ' +
  'raise rally ramp ranch random range rapid rare rate rather ratio raven ready ' +
  'real reason rebel rebuild recall receive recipe record recycle reduce reflect ' +
  'reform refuse region regret regular reject relax release relief rely remain ' +
  'remember remind remove render renew rent reopen repair repeat replace report ' +
  'require rescue resemble resist resort resource result retire retreat return reveal ' +
  'revenue review rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ' +
  'ripple risk ritual rival river road roast robot robust rocket romance roof rookie ' +
  'room rose rotate rough round route royal rubber rude rug rugby rule runner rural ' +
  'rush saddle safe sail salad salmon salon salt salute same sample sand satisfy ' +
  'satoshi sauce sausage save say scale scan scare scatter scene scheme school science ' +
  'scope score scout scrap screen script scroll sea search season seat second secret ' +
  'section security seed seek segment select sell senior sense sentence serenity ' +
  'series serve session settle setup seven shadow shaft shallow share shed shell ' +
  'sheriff shield shift shine ship shirt shiver shock shoe shoot shop short shoulder ' +
  'shout shove shrimp shrub shuffle shy sibling sick side siege sight sign silent ' +
  'silk silly silver similar simple since sing siren sister situate six size skate ' +
  'sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim ' +
  'slime slogan slope slot slush small smart smile smoke smooth snack snake snap ' +
  'sniff snow soap soccer social sock soda sofa soft solar soldier solid solution ' +
  'solve someone song soon sorry sort soul sound soup source south space spare spear ' +
  'special speed spell spend sphere spice spider spike spin spirit splash split spoil ' +
  'sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable ' +
  'staff stadium stage stamp stand staple star start state stay steak steel stem ' +
  'stereotype stick stiff still sting stock stomach stone stool stop store storm ' +
  'story stove strategy street stripe stroke structure struggle student stuff stumble ' +
  'style subject submit subway success sudden suffer sugar suggest suit summer sun ' +
  'sunny sunset super supply supreme sure surface surge surprise surround survey ' +
  'survive suspect suspend swallow swamp swap swarm swear sweat sweep sweet swift ' +
  'swim swing switch sword symbol symptom syntax system table tackle tag tail talent ' +
  'talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis ' +
  'tent term test text thank that theme then there they thick thing think third this ' +
  'thorn those though three thrice throw thumb thunder ticket tide tiger tilt timber ' +
  'time tiny tip tired tissue title toast tobacco today toddler toe toilet token ' +
  'tomato tomorrow tone tongue tonight tool tooth topic topple torch tornado tortoise ' +
  'toss total tourist toward tower town toy track trade traffic tragic train ' +
  'transfer trap trash travel tray treat tree trend trial tribe trick trigger trim ' +
  'trip trophy trouble truck truly trumpet trunk trust truth try tube tuition tumble ' +
  'tuna tunnel turn turtle twelve twenty twice twin twist two type ugly umbrella ' +
  'unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit ' +
  'universe unknown unlock until unusual unveil update upgrade upon upper upset urban ' +
  'urge usage use used useful useless usual utility valid valley valve van vanish ' +
  'vapor various vast vault vehicle velvet vendor venture venue verb verify version ' +
  'very vessel veteran viable vibrant victim victory video view village vintage violin ' +
  'virus visible vision visit vital vivid vocal voice void volcano volume vote voyage ' +
  'wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste watch ' +
  'water wave way wealth weapon weather web wedding weekend weird welcome welfare well ' +
  'west whale what wheat wheel when where whip whisper wide width wife wild will win ' +
  'window wine wing wink winner winter wipe wire wisdom wise wish witness wolf woman ' +
  'wonder wood wool word work world worry worst worth would wound wrap wreck wrestle ' +
  'wrist write wrong yard year yellow you young youth zebra zero zone zoo'
).split(/\s+/).filter(Boolean);

export { WORDLIST };
