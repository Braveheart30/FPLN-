/* FPLN uniform-of-the-day reader. One source for the app, the Command Center and control.py.
   Turns what the owner says ("ACU under Level 5 with black gloves") into the uniform and the gear in each slot,
   using the same uniform keys and gear ids as the app's UOD board (USCC Reg 670-1, Tables 3-1 to 3-4).

   Browser: window.FPLNUOD.parse(text) / .describe(k, sel) / .CATALOG
   Node:    node uodparse.js "ACU under Level 5 with black gloves"   -> JSON on stdout (exit 2 if no uniform found) */
(function(root){
  "use strict";
  var NAMES = {afc:"As for Class", wog:"White over Gray", dg:"Dress Gray", fd:"Full Dress", acu:"ACU", apfu:"APFU"};
  /* every slot's choices per uniform; the first choice is what it is with nothing said */
  var CATALOG = {
    afc: {HEAD:["gcap","scap","knit"], OUTER:["none","jacket","parka","rain"], TOP:["ss","ls"], HANDS:["none","gloves"]},
    wog: {OUTER:["none","jacket","rain"], HANDS:["none","gloves","wgloves"]},
    dg:  {OUTER:["none","overcoat","rain"], HANDS:["none","gloves","wgloves"]},
    fd:  {HEAD:["tar","svc"], OUTER:["none","overcoat","rain"], HANDS:["none","wgloves"], WAIST:["none","sash"], LEGS:["gray","white"]},
    acu: {HEAD:["pc","fleece"], OUTER:["none","l3","ecwcs","l6","l7"], NECK:["none","gaiter"], HANDS:["none","gloves"]},
    apfu:{HEAD:["none","fleece"], OUTER:["none","ajacket"], TOP:["ss","ls"], HANDS:["none","gloves"], BELT:["none","refl"], LEGS:["trunks","pants"]}
  };
  var LABEL = {gcap:"garrison cap", scap:"service cap", knit:"knit cap", jacket:"black jacket", parka:"parka", rain:"raincoat", ss:"short sleeve", ls:"long sleeve",
    gloves:"black gloves", wgloves:"white gloves", overcoat:"overcoat", tar:"tar bucket", svc:"gray service cap", sash:"red sash", white:"white trousers", gray:"gray trousers",
    pc:"patrol cap", fleece:"fleece cap", l3:"Level 3 fleece", ecwcs:"Level 5", l6:"Gore-Tex (Level 6)", l7:"Level 7 parka", gaiter:"neck gaiter",
    ajacket:"APFU jacket", refl:"reflective belt", trunks:"trunks", pants:"APFU pants", none:"none"};
  var UNI = [
    [/\b(as for class|afc|class uniform|as[- ]for[- ]class)\b/, "afc"],
    [/\b(white over gr[ae]y|w\/g|wog|whites? over gr[ae]ys?)\b/, "wog"],
    [/\b(full dress( gr[ae]y)?|fd)\b/, "fd"],
    [/\b(dress gr[ae]y|dg)\b/, "dg"],
    [/\b(acus?|a ?c ?u|ocps?|army combat uniform|combat uniform|cammies)\b/, "acu"],
    [/\b(apfus?|a ?p ?f ?u|ipfu|pt uniform|pt gear|p ?t)\b/, "apfu"]
  ];
  /* [pattern, uniforms it applies to (null = any that has the slot), slot, choice] - more specific first */
  var RULES = [
    [/\b(no|without|minus) gloves\b/, null, "HANDS", "none"],
    [/\bwhite gloves\b/, null, "HANDS", "wgloves"],
    [/\b(black |leather |cold weather |winter |dress )?gloves\b/, null, "HANDS", "gloves"],
    [/\b(fleece cap|fleece hat|beanie|watch cap|micro ?fleece cap|black cap)\b/, ["acu","apfu"], "HEAD", "fleece"],
    [/\b(knit cap|knit hat|watch cap|beanie)\b/, ["afc"], "HEAD", "knit"],
    [/\bpatrol cap\b/, ["acu"], "HEAD", "pc"],
    [/\bgarrison cap\b/, ["afc"], "HEAD", "gcap"],
    [/\b(tar ?bucket|shako|plume)\b/, ["fd"], "HEAD", "tar"],
    [/\b(service cap|gr[ae]y cap|saucer cap|bus driver cap)\b/, ["afc"], "HEAD", "scap"],
    [/\b(service cap|gr[ae]y cap)\b/, ["fd"], "HEAD", "svc"],
    [/\b(neck gaiter|gaiter|neck warmer|buff)\b/, ["acu"], "NECK", "gaiter"],
    [/\b(level (3|three|iii)|l ?3|grid ?fleece jacket|fleece jacket|fleece top|fleece)\b/, ["acu"], "OUTER", "l3"],
    [/\b(level (5|five|v)|l ?5|soft ?shell|ecwcs)\b/, ["acu"], "OUTER", "ecwcs"],
    [/\b(level (6|six|vi)|l ?6|gore[- ]?tex|gortex|gore tex|goretex|wet weather( jacket| top)?|rain jacket)\b/, ["acu"], "OUTER", "l6"],
    [/\b(level (7|seven|vii)|l ?7|puffy|puffer|extreme cold( weather)?( parka| jacket)?|parka)\b/, ["acu"], "OUTER", "l7"],
    [/\b(no (jacket|coat|outer layer|outerwear)|without (a )?(jacket|coat))\b/, null, "OUTER", "none"],
    [/\b(parka)\b/, ["afc"], "OUTER", "parka"],
    [/\b(raincoat|rain coat|rain jacket|rain gear|cape)\b/, ["afc","wog","dg","fd"], "OUTER", "rain"],
    [/\b(over ?coat|long overcoat|long coat)\b/, ["dg","fd"], "OUTER", "overcoat"],
    [/\b(apfu jacket|pt jacket|black and gold jacket|jacket)\b/, ["apfu"], "OUTER", "ajacket"],
    [/\b(black jacket|windbreaker|jacket)\b/, ["afc","wog"], "OUTER", "jacket"],
    [/\b(long[- ]?sleeves?|l\/s|ls)\b/, ["afc","apfu"], "TOP", "ls"],
    [/\b(short[- ]?sleeves?|s\/s|ss)\b/, ["afc","apfu"], "TOP", "ss"],
    [/\b(reflective( belt)?|ref(lective)? belt|pt belt|road guard belt|belt)\b/, ["apfu"], "BELT", "refl"],
    [/\b(apfu pants|pt pants|pants|long pants|sweat ?pants|trousers)\b/, ["apfu"], "LEGS", "pants"],
    [/\b(trunks|shorts)\b/, ["apfu"], "LEGS", "trunks"],
    [/\b(red )?sash\b/, ["fd"], "WAIST", "sash"],
    [/\b(over white|white trousers|white pants|whites)\b/, ["fd"], "LEGS", "white"],
    [/\b(over gr[ae]y|gr[ae]y trousers)\b/, ["fd"], "LEGS", "gray"]
  ];
  var FILLER = /\b(the|a|an|uniform|of|for|day|is|are|today|tonight|tomorrow|wear|wearing|in|with|and|under|plus|also|over|on|all|cadets|corps|formation|uod|please|sir|maam|ma'am|w|its|it's|will|be|to|at|on top|top|layer|layers|outer|optional)\b/g;
  function norm(t){ return String(t || "").toLowerCase().replace(/[‘’]/g, "'").replace(/[^a-z0-9\/'\- ]+/g, " ")
    .replace(/\bwith\b/g, " with ").replace(/\s+/g, " ").trim(); }
  function parse(text){
    var raw = String(text || "").slice(0, 300), t = " " + norm(raw) + " ", k = "", at = 1e9, res = {k:"", sel:{}, unknown:[], text:"", input:raw.trim(), when:""};
    UNI.forEach(function(u){ var m = u[0].exec(t); if(m && m.index < at){ at = m.index; k = u[1]; } });
    if(/\btomorrow\b/.test(t)) res.when = "tomorrow"; else if(/\btoday\b|\btonight\b/.test(t)) res.when = "today";
    if(!k) { res.unknown = left(t).split(" ").filter(Boolean); return res; }
    res.k = k;
    var rest = t; UNI.forEach(function(u){ rest = rest.replace(new RegExp(u[0].source, "g"), " "); });
    RULES.forEach(function(r){
      var slots = CATALOG[k]; if(!slots[r[2]] || (r[1] && r[1].indexOf(k) < 0) || slots[r[2]].indexOf(r[3]) < 0) return;
      var re = new RegExp(r[0].source, "g"); if(!re.test(rest)) return;
      if(res.sel[r[2]] === undefined) res.sel[r[2]] = r[3];
      rest = rest.replace(new RegExp(r[0].source, "g"), " ");
    });
    res.unknown = left(rest).split(" ").filter(function(w){ return w.length > 1; });
    res.text = describe(k, res.sel);
    return res;
  }
  function left(t){ return t.replace(FILLER, " ").replace(/[\/'\-]/g, " ").replace(/\s+/g, " ").trim(); }
  /* the official one-line read, built from the gear so it always matches the cadet on screen */
  function describe(k, sel){
    var c = CATALOG[k]; if(!c) return ""; sel = sel || {};
    function pick(s){ var v = sel[s]; return c[s] && c[s].indexOf(v) >= 0 ? v : null; }
    var out = NAMES[k];
    if(k === "fd"){ out += pick("LEGS") === "white" ? " over White" : " over Gray"; }
    var top = pick("TOP"); if(top) out += ", " + LABEL[top];
    var o = pick("OUTER"); if(o && o !== "none") out += " under " + LABEL[o];
    var extra = [];
    ["HEAD", "NECK", "HANDS", "BELT", "WAIST", "LEGS"].forEach(function(s){ var v = pick(s); if(!v || v === "none" || v === c[s][0]) return; if(k === "fd" && s === "LEGS") return; extra.push(LABEL[v]); });
    if(extra.length) out += " with " + (extra.length > 1 ? extra.slice(0, -1).join(", ") + " and " + extra[extra.length - 1] : extra[0]);
    return out;
  }
  /* only known uniforms, slots and choices survive (used before anything is sent or shown) */
  function clean(o){
    if(!o || !CATALOG[o.k]) return null; var sel = {};
    Object.keys(o.sel || {}).forEach(function(s){ if(CATALOG[o.k][s] && CATALOG[o.k][s].indexOf(o.sel[s]) >= 0) sel[s] = o.sel[s]; });
    return {k:o.k, sel:sel, text:String(o.text || describe(o.k, sel)).replace(/[\u0000-\u001f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, 200)};
  }
  var API = {parse:parse, describe:describe, clean:clean, CATALOG:CATALOG, NAMES:NAMES, LABEL:LABEL};
  if(typeof module !== "undefined" && module.exports){
    module.exports = API;
    if(require.main === module){ var r = parse(process.argv.slice(2).join(" ")); process.stdout.write(JSON.stringify(r) + "\n"); process.exit(r.k ? 0 : 2); }
  } else root.FPLNUOD = API;
})(typeof window !== "undefined" ? window : this);
