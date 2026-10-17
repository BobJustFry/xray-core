//go:build race

package splithttp

// sync.Pool в режиме -race случайно теряет положенное (Put) — проверки пула мягче.
const vupenRaceEnabled = true
