package server

import (
	"sort"
	"sync"
)

var (
	highScoresMutex sync.Mutex
	userGamesMutex  sync.Mutex
)

func UpdateHighScores(username string, score int) {
	highScoresMutex.Lock()
	defer highScoresMutex.Unlock()

	for i, hs := range highScores {
		if hs.Username == username {
			if score > hs.Score {
				highScores[i].Score = score
			}
			sort.Slice(highScores, func(i, j int) bool {
				return highScores[i].Score > highScores[j].Score
			})
			return
		}
	}
	highScores = append(highScores, HighScore{Username: username, Score: score})
	sort.Slice(highScores, func(i, j int) bool {
		return highScores[i].Score > highScores[j].Score
	})
	if len(highScores) > 10 {
		highScores = highScores[:10]
	}
}

func ViewLastGames(username string) []Game {
	userGamesMutex.Lock()
	defer userGamesMutex.Unlock()
	return userGames[username]
}

func AddGame(username string, score int, level int, time string) {
	userGamesMutex.Lock()
	defer userGamesMutex.Unlock()

	game := Game{
		Score: score,
		Level: level,
		Time:  time,
	}
	userGames[username] = append(userGames[username], game)
	if len(userGames[username]) > 10 {
		userGames[username] = userGames[username][:10]
	}
}
