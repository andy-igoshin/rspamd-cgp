package cgp

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/maypok86/otter"
	"golang.org/x/sync/singleflight"
)

var (
	dnsResolver = &net.Resolver{PreferGo: true}
	sfGroup     singleflight.Group
)

func filterNames(names []string) []string {

	fqdn := make([]string, 0, len(names))
	nonfqdn := make([]string, 0, len(names))

	for _, name := range names {
		if IsValidDomain(name) {
			fqdn = append(fqdn, name)
		} else {
			nonfqdn = append(nonfqdn, name)
		}
	}

	if len(fqdn) > 0 {
		return fqdn
	} else {
		return nonfqdn
	}
}

func findLongerItem(items []string) (res string) {
	if len(items) > 0 {
		var maxlen = 0
		var pos int
		for p, item := range items {
			if len(item) > maxlen {
				maxlen = len(item)
				pos = p
			}
		}
		res = items[pos]
	}
	return
}

func findShorterItem(items []string) (res string) {
	if len(items) > 0 {
		var maxlen = len(items[0])
		var pos int
		for p, item := range items {
			if len(item) < maxlen {
				maxlen = len(item)
				pos = p
			}
		}
		res = items[pos]
	}
	return
}

var getHostname = func() func(addr string) (hostname string) {

	cache, _ := otter.MustBuilder[netip.Addr, string](1000).
		CollectStats().
		Cost(func(key netip.Addr, value string) uint32 {
			return 1
		}).
		WithVariableTTL().
		Build()

	return func(addr string) (hostname string) {

		ipAddr, err := netip.ParseAddr(addr)
		if err != nil {
			return
		}

		// Fast path: read from in-memory cache
		if h, ok := cache.Get(ipAddr); ok {
			return h
		}

		// Slow path: singleflight prevents duplicate DNS lookups
		// when multiple goroutines resolve the same IP simultaneously.
		res, _, _ := sfGroup.Do(addr, func() (any, error) {
			// Double-check: another goroutine may have filled the cache
			if h, ok := cache.Get(ipAddr); ok {
				return h, nil
			}

			h := lookupAddr(ipAddr)
			if len(h) > 0 {
				cache.Set(ipAddr, h, time.Hour)
			} else {
				cache.Set(ipAddr, h, 5*time.Minute)
			}
			return h, nil
		})

		return res.(string)
	}
}()

func IsValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Fast path: IP-адреса (v4 и v6) обычно начинаются с цифры или двоеточия.
	// Домены по RFC могут начинаться с цифры, но это редкость.
	// Если первый символ - цифра или ':', проверяем, не IP ли это.
	first := domain[0]
	if (first >= '0' && first <= '9') || first == ':' {
		if _, err := netip.ParseAddr(strings.TrimSuffix(domain, ".")); err == nil {
			return false // Это чистый IP
		}
	}

	domain = strings.TrimSuffix(domain, ".")
	lastDot := -1
	hasDot := false

	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if c == '.' {
			labelLen := i - lastDot - 1
			// Пустые метки (..) или дефис по краям метки недопустимы
			if labelLen == 0 || labelLen > 63 || domain[lastDot+1] == '-' || domain[i-1] == '-' {
				return false
			}
			lastDot = i
			hasDot = true
			continue
		}

		// Допустимые символы: [a-zA-Z0-9_-]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}

	// Проверка последней метки (TLD)
	finalLabelLen := len(domain) - lastDot - 1
	if finalLabelLen == 0 || finalLabelLen > 63 || domain[lastDot+1] == '-' || domain[len(domain)-1] == '-' {
		return false
	}

	return hasDot
}

func lookupAddr(ipAddr netip.Addr) (hostname string) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	names, err := dnsResolver.LookupAddr(ctx, ipAddr.String())
	if err != nil {
		return
	}

	if len(names) == 1 {
		hostname = strings.TrimSuffix(names[0], ".")
		return
	}

	type result struct{ name string }
	ch := make(chan result, len(names))

	for _, name := range names {
		go func(name string) {
			ips, err := dnsResolver.LookupHost(ctx, name)
			if err != nil {
				ch <- result{}
				return
			}
			for _, ip := range ips {
				ipTest, err := netip.ParseAddr(ip)
				if err != nil {
					continue
				}
				if ipTest == ipAddr {
					ch <- result{name}
					return
				}
			}
			ch <- result{}
		}(name)
	}

	found := make([]string, 0, len(names))
	for range names {
		if r := <-ch; r.name != "" {
			found = append(found, r.name)
		}
	}

	switch len(found) {
	case 0:
		// если ни один name не имеет корректного прямого резольвинга
		// в исходный ip, выбираем самый длинный.
		hostname = findLongerItem(filterNames(names))

	case 1:
		hostname = found[0]

	default:
		// если несколько name имеют корректный прямой резольвинг
		// в исходный ip, выбираем самый короткий.
		hostname = findShorterItem(filterNames(found))
	}

	hostname = strings.TrimSuffix(hostname, ".")
	return
}
