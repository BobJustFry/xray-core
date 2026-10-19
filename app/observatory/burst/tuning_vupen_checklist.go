package burst

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// РЇРґСЂРѕ 85 (T-129): СЃРїРёСЃРѕРє Р°РґСЂРµСЃРѕРІ РїСЂРѕРІРµСЂРєРё РІРјРµСЃС‚Рѕ РїР°СЂС‹ В«РѕСЃРЅРѕРІРЅРѕР№ + Р·Р°РїР°СЃРЅРѕР№В».
//
// РџСЂРѕРІРµСЂРєР° РёРґС‘С‚ С‡РµСЂРµР· РїСЂРѕРІРµСЂСЏРµРјС‹Р№ СѓР·РµР», Р·РЅР°С‡РёС‚ Р°РґСЂРµСЃ РґРѕР»Р¶РµРЅ РѕС‚РєСЂС‹РІР°С‚СЊСЃСЏ СЃ РІС‹С…РѕРґР°
// СѓР·Р»Р°. РћРґРёРЅ С…РѕСЃС‚ (СЂР°РЅСЊС€Рµ С‚РѕР»СЊРєРѕ Cloudflare) РјРѕРі РѕРєР°Р·Р°С‚СЊСЃСЏ РЅРµРґРѕСЃС‚СѓРїРµРЅ вЂ” С‚РѕРіРґР° РІСЃРµ
// СѓР·Р»С‹ РІС‹РіР»СЏРґРµР»Рё Р·Р°РјРѕСЂРѕР¶РµРЅРЅС‹РјРё. РўРµРїРµСЂСЊ Р°РґСЂРµСЃРѕРІ РЅРµСЃРєРѕР»СЊРєРѕ, Сѓ СЂР°Р·РЅС‹С… РѕРїРµСЂР°С‚РѕСЂРѕРІ; СЏРґСЂРѕ
// Р·Р°РїРѕРјРёРЅР°РµС‚, РєР°РєРѕР№ РѕС‚РІРµС‡Р°Р», Рё РЅР°С‡РёРЅР°РµС‚ СЃ РЅРµРіРѕ.
//
// РџСЂР°РІРёР»Р° РѕРґРЅРѕР№ РїСЂРѕРІРµСЂРєРё (vupenRunList), РѕР±С‰РёРµ РґР»СЏ 24 РљР‘ Рё 64 РљР‘:
//   - РїРµСЂРµР±РѕСЂ РїРѕ РїРѕСЂСЏРґРєСѓ РѕС‚ Р·Р°РїРѕРјРЅРµРЅРЅРѕРіРѕ, РЅРµ Р±РѕР»СЊС€Рµ vupenCheckTries Р°РґСЂРµСЃРѕРІ Р·Р° РїСЂРѕРІРµСЂРєСѓ;
//   - С„Р°Р№Р» РґРѕС€С‘Р» вЂ” СЃС‚РѕРї, Р°РґСЂРµСЃ Р·Р°РїРѕРјРёРЅР°РµС‚СЃСЏ;
//   - СЃР»РµРґСѓСЋС‰РёР№ Р°РґСЂРµСЃ РїСЂРѕР±СѓРµРј, С‚РѕР»СЊРєРѕ РµСЃР»Рё РїСЂРѕРІР°Р» РіРѕРІРѕСЂРёС‚ Рѕ СЃР°РјРѕРј РҐРћРЎРўР• РїСЂРѕРІРµСЂРєРё, Р° РЅРµ
//     РѕР± СѓР·Р»Рµ: HTTP в‰  200 РёР»Рё РЅРµС‚ СЃРѕРµРґРёРЅРµРЅРёСЏ СЃ С…РѕСЃС‚РѕРј (РѕС‚РєР°Р·, СЂСѓРєРѕРїРѕР¶Р°С‚РёРµ, DNS, СЃР±СЂРѕСЃ
//     РґРѕ РѕС‚РІРµС‚Р°);
//   - РІСЃС‚Р°Р» РїРѕСЃСЂРµРґРё С„Р°Р№Р»Р°, РЅРµ РЅР°С‡Р°Р»СЃСЏ РІРѕРІСЂРµРјСЏ, РѕР±РѕСЂРІР°Р»СЃСЏ РїРѕСЃСЂРµРґРё С‚РµР»Р° вЂ” СЂРёСЃСѓРЅРѕРє Р·Р°РјРѕСЂРѕР·РєРё
//     СѓР·Р»Р°: Р·Р°РїР°СЃРЅРѕР№ РќР• РїСЂРѕР±СѓРµРј, СЌС‚Рѕ Рё РµСЃС‚СЊ РїСЂРѕРІР°Р»;
//   - РІСЃРµ РїСЂРѕР±РѕРІР°РЅРЅС‹Рµ Р°РґСЂРµСЃР° (РЅРµ РјРµРЅСЊС€Рµ РґРІСѓС…) РїСЂРѕРІР°Р»РёР»РёСЃСЊ В«СЃРѕ СЃС‚РѕСЂРѕРЅС‹ С…РѕСЃС‚Р°В» РѕРґРЅРёРј РІРёРґРѕРј
//     СЃРѕРµРґРёРЅРµРЅРёСЏ вЂ” РёС‚РѕРі unknown: СѓР·РµР» РЅРµ РІРёРЅРѕРІР°С‚ РІ С‚РѕРј, С‡С‚Рѕ РїСЂРѕРІРµСЂРѕС‡РЅС‹Р№ С…РѕСЃС‚ РЅРµ РѕС‚РєСЂС‹РІР°РµС‚СЃСЏ.
//     РќРћ С‚РѕР»СЊРєРѕ РїСЂРё РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРµ, С‡С‚Рѕ СѓР·РµР» Р¶РёРІ (T-131, CR-001): tagged.Dialer РЅРµ
//     РІРѕР·РІСЂР°С‰Р°РµС‚ РѕС€РёР±РєРё РЅР°Р±РѕСЂР° вЂ” РјС‘СЂС‚РІС‹Р№ СѓР·РµР» РІРёРґРµРЅ РєР°Рє В«closed pipeВ»/EOF РЅР° РѕР±РѕРёС… С…РѕСЃС‚Р°С…,
//     С‚Рѕ РµСЃС‚СЊ С‚Р°Рє Р¶Рµ, РєР°Рє РјС‘СЂС‚РІС‹Рµ С…РѕСЃС‚С‹. Р”РѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРѕ: Р»СЋР±РѕР№ РїСЂРѕР±РѕРІР°РЅРЅС‹Р№ Р°РґСЂРµСЃ РґР°Р»
//     HTTP-СЃС‚Р°С‚СѓСЃ (РѕС‚РІРµС‚ РїСЂРёС€С‘Р» С‡РµСЂРµР· СѓР·РµР», РїСѓСЃС‚СЊ 404) Р»РёР±Рѕ Сѓ СѓР·Р»Р° СЃРІРµР¶Р°СЏ СѓРґР°С‡РЅР°СЏ РїСЂРѕР±Р°
//     РѕР±СЃРµСЂРІР°С‚РѕСЂРёРё (vupenAliveProofAge). РќРµС‚ РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІР° вЂ” РѕСЃС‚Р°С‘С‚СЃСЏ РїСЂРѕРІР°Р» (failed).

// РђРґСЂРµСЃР° РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ: С‚СЂРё РѕРїРµСЂР°С‚РѕСЂР°, Cloudflare РїРѕСЃР»РµРґРЅРёРј. Р¤Р°Р№Р» jQuery вЂ” 87 533 Р±Р°Р№С‚Р°:
// СЏРґСЂРѕ С‡РёС‚Р°РµС‚ С‚РµР»Рѕ С†РµР»РёРєРѕРј Рё СЃРІРµСЂСЏРµС‚ СЃ Content-Length, С‚Р°Рє С‡С‚Рѕ РѕРЅ РіРѕРґРёС‚СЃСЏ Рё РґР»СЏ 24 РљР‘, Рё
// РґР»СЏ 64 РљР‘. РЈ Cloudflare СЂР°Р·РјРµСЂ Р·Р°РґР°С‘С‚ РїР°СЂР°РјРµС‚СЂ bytes.
var (
	VupenCheckDefaultURLs = []string{
		"https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js",
		"https://code.jquery.com/jquery-3.7.1.min.js",
		"https://speed.cloudflare.com/__down?bytes=24576",
	}
	VupenTspuDefaultURLs = []string{
		"https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js",
		"https://code.jquery.com/jquery-3.7.1.min.js",
		"https://speed.cloudflare.com/__down?bytes=65536",
	}
)

// vupenAliveProofAge вЂ” РЅР°СЃРєРѕР»СЊРєРѕ СЃРІРµР¶РµР№ РґРѕР»Р¶РЅР° Р±С‹С‚СЊ СѓРґР°С‡РЅР°СЏ РїСЂРѕР±Р° СѓР·Р»Р°, С‡С‚РѕР±С‹ СЃС‡РёС‚Р°С‚СЊСЃСЏ
// РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРѕРј РµРіРѕ Р¶РёР·РЅРё РїСЂРё РЅРµРґРѕСЃС‚СѓРїРЅС‹С… С…РѕСЃС‚Р°С… РїСЂРѕРІРµСЂРєРё.
var vupenAliveProofAge = 60 * time.Second

const (
	vupenCheckTries   = 2 // Р°РґСЂРµСЃРѕРІ РЅР° РѕРґРЅСѓ РїСЂРѕРІРµСЂРєСѓ
	vupenCheckListMax = 8 // Р°РґСЂРµСЃРѕРІ РІ СЃРїРёСЃРєРµ, С‡С‚Рѕ РїСЂРёРЅРёРјР°РµС‚ СЃРµС‚С‚РµСЂ
)

// vupenURLList вЂ” Р·Р°РґР°РЅРЅС‹Р№ РїР»Р°С‚С„РѕСЂРјРѕР№ СЃРїРёСЃРѕРє Рё РЅРѕРјРµСЂ Р°РґСЂРµСЃР°, РєРѕС‚РѕСЂС‹Р№ РѕС‚РІРµС‡Р°Р» РІ РїРѕСЃР»РµРґРЅРёР№ СЂР°Р·.
type vupenURLList struct {
	set    atomic.Pointer[[]string]
	winner atomic.Int32
}

// store вЂ” РЅРѕРІС‹Р№ СЃРїРёСЃРѕРє; С‚РѕС‚ Р¶Рµ СЃРїРёСЃРѕРє (РїСЂРёР»РѕР¶РµРЅРёРµ Р·РѕРІС‘С‚ РЅР° РєР°Р¶РґРѕРј Р·Р°РїСѓСЃРєРµ) РїР°РјСЏС‚СЊ РЅРµ СЃР±СЂР°СЃС‹РІР°РµС‚.
func (l *vupenURLList) store(urls []string) {
	if old := l.set.Load(); old == nil || !slices.Equal(*old, urls) {
		l.winner.Store(0)
	}
	cp := slices.Clone(urls)
	l.set.Store(&cp)
}

func (l *vupenURLList) reset() {
	l.set.Store(nil)
	l.winner.Store(0)
}

var (
	vupenCheckURLs vupenURLList // 24 РљР‘ (VupenSetCheckURL)
	vupenTspuURLs  vupenURLList // 64 РљР‘ (VupenSetTspuURLs)
)

// vupenURLsOf вЂ” [primary] + Р°РґСЂРµСЃР° РёР· fallback (С‡РµСЂРµР· РїСЂРѕР±РµР»/РїРµСЂРµРІРѕРґ СЃС‚СЂРѕРєРё), Р±РµР· РїРѕРІС‚РѕСЂРѕРІ Рё РїСѓСЃС‚С‹С….
func vupenURLsOf(primary, fallback string) []string {
	var out []string
	for _, u := range append([]string{primary}, strings.Fields(fallback)...) {
		if u != "" && !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

// vupenValidURLs вЂ” РїСЂРѕРІРµСЂРєР° Р°РґСЂРµСЃРѕРІ СЃРµС‚С‚РµСЂР°: "" вЂ” РіРѕРґСЏС‚СЃСЏ. РћС€РёР±РєР° РЅР°С‡РёРЅР°РµС‚СЃСЏ СЃ РёРјРµРЅРё СЃР»РѕС‚Р°.
func vupenValidURLs(urls []string) string {
	if len(urls) == 0 {
		return "primary: empty"
	}
	if len(urls) > vupenCheckListMax {
		return "too many urls"
	}
	for i, u := range urls {
		if e := VupenCheckURLError(u); e != "" {
			if i == 0 {
				return "primary: " + e
			}
			return "fallback: " + e
		}
	}
	return ""
}

// vupenCheckList вЂ” Р°РґСЂРµСЃР° 24 РљР‘ СЃРµР№С‡Р°СЃ: Р·Р°РґР°РЅРЅС‹Рµ РїР»Р°С‚С„РѕСЂРјРѕР№, РёРЅР°С‡Рµ РїРµСЂРµРјРµРЅРЅС‹Рµ
// VupenStickyCheckURL/FallbackURL (С‚РµСЃС‚С‹ Рё РїСЂРµР¶РЅРёРµ РІС‹Р·РѕРІС‹), РёРЅР°С‡Рµ СѓРјРѕР»С‡Р°РЅРёРµ.
func vupenCheckList() []string {
	if p := vupenCheckURLs.set.Load(); p != nil {
		return *p
	}
	if VupenStickyCheckURL != "" {
		return vupenURLsOf(VupenStickyCheckURL, VupenStickyCheckFallbackURL)
	}
	return VupenCheckDefaultURLs
}

// vupenTspuList вЂ” Р°РґСЂРµСЃР° 64 РљР‘ СЃРµР№С‡Р°СЃ (С‚РѕР»СЊРєРѕ С„Р°Р№Р»С‹ РЅРµ РјРµРЅСЊС€Рµ 64 РљР‘).
func vupenTspuList() []string {
	if p := vupenTspuURLs.set.Load(); p != nil {
		return *p
	}
	if VupenTspuURL != "" {
		return []string{VupenTspuURL}
	}
	return VupenTspuDefaultURLs
}

// VupenSetTspuURLs вЂ” Р°РґСЂРµСЃР° РїСЂРѕРІРµСЂРєРё 64 РљР‘ РїРѕ РїРѕСЂСЏРґРєСѓ (С‚РѕР»СЊРєРѕ https СЃ РёРјРµРЅРµРј СѓР·Р»Р°,
// С„Р°Р№Р»С‹ РќР• РјРµРЅСЊС€Рµ VupenTspuBytes: РјРµРЅСЊС€РёР№ С„Р°Р№Р» В«РїСЂРѕРІРµСЂРёР»В» Р±С‹ СѓР·РµР» РЅРµ С‚РµРј РѕР±СЉС‘РјРѕРј).
// РћС€РёР±РєР° вЂ” С‚РµРєСЃС‚, Р°РґСЂРµСЃР° РЅРµ РјРµРЅСЏСЋС‚СЃСЏ; "" вЂ” РїСЂРёРЅСЏС‚Рѕ.
//
// Р’ libXray Рё libv2ray (РјРѕСЃС‚С‹ iOS/macOS/Android) СЌС‚Р° С„СѓРЅРєС†РёСЏ РќР• РІС‹РІРµРґРµРЅР° (T-131, CR-007):
// РїР»Р°С‚С„РѕСЂРјС‹ РїСЂРѕРІРµСЂСЏСЋС‚ 64 РљР‘ РїРѕ VupenTspuDefaultURLs. РњРµРЅСЏС‚СЊ СЃРїРёСЃРѕРє 64 РљР‘ СЃ РїР»Р°С‚С„РѕСЂРјС‹
// РјРѕР¶РЅРѕ С‚РѕР»СЊРєРѕ РґРѕР±Р°РІРёРІ РјРѕСЃС‚ вЂ” СЌС‚Рѕ РѕС‚РґРµР»СЊРЅР°СЏ Р·Р°РґР°С‡Р°.
func VupenSetTspuURLs(urls []string) string {
	if e := vupenValidURLs(urls); e != "" {
		return e
	}
	vupenTspuURLs.store(urls)
	return ""
}

// vupenFailSide вЂ” С‡РµР№ СЌС‚Рѕ РїСЂРѕРІР°Р»: С…РѕСЃС‚Р° РїСЂРѕРІРµСЂРєРё (host) РёР»Рё СѓР·Р»Р°. connect вЂ” РІРёРґ РѕС€РёР±РєРё
// СЃРѕРµРґРёРЅРµРЅРёСЏ ("" вЂ” СЌС‚Рѕ РЅРµ РѕС€РёР±РєР° СЃРѕРµРґРёРЅРµРЅРёСЏ: HTTP в‰  200).
func vupenFailSide(r vupenDownloadResult) (host bool, connect string) {
	switch {
	case r.status != 0 && r.status != 200:
		return true, ""
	case r.status == 0 && !r.started && !r.stalled && !r.timedOut && r.err != nil:
		return true, vupenConnectKind(r.err)
	}
	return false, ""
}

func vupenConnectKind(err error) string {
	s := strings.ToLower(err.Error())
	has := func(subs ...string) bool {
		for _, x := range subs {
			if strings.Contains(s, x) {
				return true
			}
		}
		return false
	}
	switch {
	case has("no such host", "lookup ", "dns"):
		return "dns"
	case has("refused"):
		return "refused"
	case has("tls:", "x509", "certificate", "handshake"):
		return "tls"
	case has("reset", "eof", "broken pipe", "closed"):
		return "reset"
	}
	return "other"
}

type vupenTry struct {
	url string
	r   vupenDownloadResult
}

type vupenListRun struct {
	tries []vupenTry
	ok    bool
	// hostDead вЂ” РЅРё РѕРґРёРЅ Р°РґСЂРµСЃ РЅРµ СѓР»РѕР¶РёР»СЃСЏ, Р° РІСЃРµ РїСЂРѕРІР°Р»С‹ В«СЃРѕ СЃС‚РѕСЂРѕРЅС‹ С…РѕСЃС‚Р°В» РѕРґРЅРѕРіРѕ РІРёРґР°
	// СЃРѕРµРґРёРЅРµРЅРёСЏ (РёС‚РѕРі unknown). РќСѓР¶РЅРѕ РЅРµ РјРµРЅСЊС€Рµ РґРІСѓС… РїСЂРѕР±РѕРІР°РЅРЅС‹С… Р°РґСЂРµСЃРѕРІ: РїРѕ РѕРґРЅРѕРјСѓ
	// РЅРµР»СЊР·СЏ РѕС‚Р»РёС‡РёС‚СЊ С…РѕСЃС‚ РїСЂРѕРІРµСЂРєРё РѕС‚ РјС‘СЂС‚РІРѕРіРѕ СѓР·Р»Р°; Рё РЅСѓР¶РЅРѕ РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРѕ Р¶РёР·РЅРё СѓР·Р»Р°
	// (HTTP-СЃС‚Р°С‚СѓСЃ Р»СЋР±РѕРіРѕ Р°РґСЂРµСЃР° Р»РёР±Рѕ СЃРІРµР¶Р°СЏ РїСЂРѕР±Р°, vupenAliveProofAge).
	hostDead bool
}

func (x vupenListRun) last() vupenTry { return x.tries[len(x.tries)-1] }

func (x vupenListRun) elapsed() (d time.Duration) {
	for _, t := range x.tries {
		d += t.r.elapsed
	}
	return d
}

// vupenRunList вЂ” РїСЂРѕРІРµСЂРєР° РїРѕ РїСЂР°РІРёР»Р°Рј СЃРїРёСЃРєР°. l != nil вЂ” СЃРїРёСЃРѕРє РїР»Р°С‚С„РѕСЂРјС‹: СЃС‚Р°СЂС‚ СЃ
// Р·Р°РїРѕРјРЅРµРЅРЅРѕРіРѕ Р°РґСЂРµСЃР°, РІС‹РёРіСЂР°РІС€РёР№ Р·Р°РїРѕРјРёРЅР°РµС‚СЃСЏ; nil вЂ” Р·Р°РґР°РЅРЅС‹Рµ РІС‹Р·С‹РІР°СЋС‰РёРј Р°РґСЂРµСЃР°, Р±РµР· РїР°РјСЏС‚Рё.
// allow (РјРѕР¶РµС‚ Р±С‹С‚СЊ nil) вЂ” СѓРєР»Р°РґС‹РІР°РµРјСЃСЏ Р»Рё РІ Р±СЋРґР¶РµС‚, СЃРїСЂР°С€РёРІР°РµС‚СЃСЏ РїРµСЂРµРґ РєР°Р¶РґС‹Рј СЃР»РµРґСѓСЋС‰РёРј Р°РґСЂРµСЃРѕРј.
// alive (РјРѕР¶РµС‚ Р±С‹С‚СЊ nil) вЂ” РµСЃС‚СЊ Р»Рё Сѓ СѓР·Р»Р° СЃРІРµР¶Р°СЏ СѓРґР°С‡РЅР°СЏ РїСЂРѕР±Р° (РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІРѕ Р¶РёР·РЅРё, CR-001);
// СЃРїСЂР°С€РёРІР°РµС‚СЃСЏ С‚РѕР»СЊРєРѕ РєРѕРіРґР° РѕР±Р° С…РѕСЃС‚Р° РїСЂРѕРІР°Р»РёР»РёСЃСЊ, Р° СЃС‚Р°С‚СѓСЃР° РЅРµ Р±С‹Р»Рѕ.
func vupenRunList(ctx context.Context, l *vupenURLList, urls []string, allow func() bool, alive func() bool,
	isOK func(vupenDownloadResult) bool, do func(url string) vupenDownloadResult) vupenListRun {
	var run vupenListRun
	if len(urls) == 0 {
		return run
	}
	start := 0
	if l != nil {
		start = int(l.winner.Load())
		if start < 0 || start >= len(urls) {
			start = 0
		}
	}
	for i := 0; i < len(urls) && i < vupenCheckTries; i++ {
		if i > 0 && (ctx.Err() != nil || (allow != nil && !allow())) {
			break
		}
		idx := (start + i) % len(urls)
		r := do(urls[idx])
		run.tries = append(run.tries, vupenTry{urls[idx], r})
		if isOK(r) {
			run.ok = true
			if l != nil {
				l.winner.Store(int32(idx))
			}
			return run
		}
		if host, _ := vupenFailSide(r); !host {
			return run // СЂРёСЃСѓРЅРѕРє Р·Р°РјРѕСЂРѕР·РєРё СѓР·Р»Р°: Р·Р°РїР°СЃРЅРѕР№ РЅРµ РЅСѓР¶РµРЅ
		}
	}
	if len(run.tries) >= 2 {
		kind, dead, proof := "", true, false
		for _, t := range run.tries {
			if t.r.status != 0 {
				proof = true // РѕС‚РІРµС‚ РїСЂРёС€С‘Р» С‡РµСЂРµР· СѓР·РµР» (Р·РґРµСЃСЊ СЌС‚Рѕ HTTP в‰  200)
			}
			host, k := vupenFailSide(t.r)
			if !host {
				dead = false
				break
			}
			if k != "" {
				if kind != "" && kind != k {
					dead = false
					break
				}
				kind = k
			}
		}
		if dead && !proof && alive != nil {
			proof = alive()
		}
		run.hostDead = dead && proof
	}
	return run
}

// vupenNodeAlive вЂ” Сѓ СѓР·Р»Р° tag РµСЃС‚СЊ СѓРґР°С‡РЅР°СЏ РїСЂРѕР±Р° РѕР±СЃРµСЂРІР°С‚РѕСЂРёРё РЅРµ СЃС‚Р°СЂС€Рµ vupenAliveProofAge.
func (h *HealthPing) vupenNodeAlive(tag string) bool {
	h.access.Lock()
	defer h.access.Unlock()
	r, ok := h.Results[tag]
	if !ok {
		return false
	}
	var newestOK, newestFail time.Time
	for _, x := range r.rtts {
		if x == nil || x.value == rttUntested || x.time.IsZero() {
			continue
		}
		if x.value == rttFailed {
			if x.time.After(newestFail) {
				newestFail = x.time
			}
		} else if x.time.After(newestOK) {
			newestOK = x.time
		}
	}
	// CR-101: СЃР°РјР°СЏ СЃРІРµР¶Р°СЏ РїСЂРѕР±Р° вЂ” РїСЂРѕРІР°Р» (РЅРµ СЃС‚Р°СЂС€Рµ СѓРґР°С‡Рё) в†’ СѓР·РµР» РјРѕРі СѓРјРµСЂРµС‚СЊ РїРѕСЃР»Рµ СѓРґР°С‡Рё.
	if !newestFail.IsZero() && !newestFail.Before(newestOK) {
		return false
	}
	return !newestOK.IsZero() && time.Since(newestOK) <= vupenAliveProofAge
}
