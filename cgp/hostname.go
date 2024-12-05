package cgp

import (
	"context"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/maypok86/otter"
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

		hostname, ok := cache.Get(ipAddr)
		if !ok {
			hostname = lookupAddr(ipAddr)
			if len(hostname) > 0 {
				cache.Set(ipAddr, hostname, time.Hour)
			} else {
				cache.Set(ipAddr, hostname, 5*time.Minute)
			}
		}

		return
	}
}()

var IsValidDomain = func() func(domain string) bool {
	rx := regexp.MustCompile(`^(?i)[a-z0-9-]+(\.[a-z0-9-]+)+\.?$`)
	return func(domain string) bool {
		return rx.MatchString(domain)
	}
}()

func lookupAddr(ipAddr netip.Addr) (hostname string) {

	r := &net.Resolver{PreferGo: true}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	names, err := r.LookupAddr(ctx, ipAddr.String())
	cancel()
	if err != nil {
		return
	}

	if len(names) == 1 {
		hostname = names[0]
	} else if len(names) > 1 {

		found := make([]string, 0, len(names))

		for _, name := range names {

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			ips, err := r.LookupHost(ctx, name)
			cancel()
			if err != nil {
				return
			}

			for _, ip := range ips {
				ipTest, err := netip.ParseAddr(ip)
				if err != nil {
					continue
				}
				if ipTest == ipAddr {
					found = append(found, name)
					break
				}
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
	}

	if len(hostname) > 0 {
		hostname = strings.TrimSuffix(hostname, ".")
	}

	return
}
