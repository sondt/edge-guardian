package config

import (
	"reflect"
	"testing"
)

func TestTelegramRecipients(t *testing.T) {
	tests := []struct {
		name string
		c    TelegramConfig
		want []string
	}{
		{"single chat_id", TelegramConfig{ChatID: "123"}, []string{"123"}},
		{"chat_ids only", TelegramConfig{ChatIDs: []string{"123", "456"}}, []string{"123", "456"}},
		{
			"merge + dedup + order",
			TelegramConfig{ChatID: "123", ChatIDs: []string{"456", "123", "789"}},
			[]string{"123", "456", "789"},
		},
		{"trims blanks", TelegramConfig{ChatID: " ", ChatIDs: []string{"  ", "42"}}, []string{"42"}},
		{"none", TelegramConfig{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.Recipients(); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Recipients() = %v, want %v", got, tt.want)
			}
		})
	}
}
