package policy

import (
	"fmt"
	"strings"
	"time"
)

type timeWindowSchedule struct {
	days     uint8
	start    int
	end      int
	location *time.Location
}

// CompiledTimeWindow is the normalized, exporter-friendly form of a policy
// time window. Days use Go's time.Weekday numbering (Sunday = 0).
type CompiledTimeWindow struct {
	Days        []int  `json:"days" yaml:"days"`
	StartMinute int    `json:"startMinute" yaml:"startMinute"`
	EndMinute   int    `json:"endMinute" yaml:"endMinute"`
	Timezone    string `json:"timezone" yaml:"timezone"`
}

// CompileTimeWindow validates and normalizes a human-readable policy window.
func CompileTimeWindow(spec string) (CompiledTimeWindow, error) {
	parsed, err := parseTimeWindow(spec)
	if err != nil {
		return CompiledTimeWindow{}, err
	}
	days := make([]int, 0, 7)
	for day := 0; day < 7; day++ {
		if parsed.days&(1<<uint(day)) != 0 {
			days = append(days, day)
		}
	}
	return CompiledTimeWindow{
		Days:        days,
		StartMinute: parsed.start,
		EndMinute:   parsed.end,
		Timezone:    parsed.location.String(),
	}, nil
}

var weekdayNames = map[string]time.Weekday{
	"Sun": time.Sunday,
	"Mon": time.Monday,
	"Tue": time.Tuesday,
	"Wed": time.Wednesday,
	"Thu": time.Thursday,
	"Fri": time.Friday,
	"Sat": time.Saturday,
}

func parseTimeWindow(spec string) (*timeWindowSchedule, error) {
	fields := strings.Fields(spec)
	if len(fields) != 3 {
		return nil, fmt.Errorf("time window %q must use '<days> HH:MM-HH:MM <IANA timezone>'", spec)
	}
	days, err := parseDays(fields[0])
	if err != nil {
		return nil, err
	}
	start, end, err := parseClockRange(fields[1])
	if err != nil {
		return nil, err
	}
	location, err := time.LoadLocation(fields[2])
	if err != nil {
		return nil, fmt.Errorf("time window %q has unknown timezone %q", spec, fields[2])
	}
	return &timeWindowSchedule{days: days, start: start, end: end, location: location}, nil
}

func parseDays(spec string) (uint8, error) {
	if spec == "*" {
		return 0x7f, nil
	}
	var result uint8
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return 0, fmt.Errorf("time window has an empty day selector")
		}
		parts := strings.Split(token, "-")
		if len(parts) > 2 {
			return 0, fmt.Errorf("invalid day range %q", token)
		}
		start, ok := weekdayNames[parts[0]]
		if !ok {
			return 0, fmt.Errorf("invalid weekday %q", parts[0])
		}
		end := start
		if len(parts) == 2 {
			end, ok = weekdayNames[parts[1]]
			if !ok {
				return 0, fmt.Errorf("invalid weekday %q", parts[1])
			}
		}
		for day := start; ; day = (day + 1) % 7 {
			result |= 1 << uint(day)
			if day == end {
				break
			}
		}
	}
	return result, nil
}

func parseClockRange(spec string) (int, int, error) {
	parts := strings.Split(spec, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid time range %q", spec)
	}
	start, err := parseClock(parts[0])
	if err != nil {
		return 0, 0, err
	}
	end, err := parseClock(parts[1])
	if err != nil {
		return 0, 0, err
	}
	return start, end, nil
}

func parseClock(value string) (int, error) {
	parsed, err := time.Parse("15:04", value)
	if err != nil {
		return 0, fmt.Errorf("invalid time %q; expected HH:MM", value)
	}
	return parsed.Hour()*60 + parsed.Minute(), nil
}

func (window *timeWindowSchedule) outside(at time.Time) bool {
	local := at.In(window.location)
	minute := local.Hour()*60 + local.Minute()
	today := int(local.Weekday())
	yesterday := (today + 6) % 7
	selected := func(day int) bool { return window.days&(1<<uint(day)) != 0 }

	var inside bool
	switch {
	case window.start < window.end:
		inside = selected(today) && minute >= window.start && minute < window.end
	case window.start > window.end:
		inside = selected(today) && minute >= window.start || selected(yesterday) && minute < window.end
	default:
		inside = selected(today)
	}
	return !inside
}
