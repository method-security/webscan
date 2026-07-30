package task

import "encoding/xml"

// Triggers corresponds to the <Triggers> container (triggersType)
// and may hold any number of each trigger type, in schema order.
type Triggers struct {
  XMLName            xml.Name                    `xml:"Triggers"`
  Boot               []BootTrigger               `xml:"BootTrigger,omitempty"`
  Time               []TimeTrigger               `xml:"TimeTrigger,omitempty"`
  Calendar           []CalendarTrigger           `xml:"CalendarTrigger,omitempty"`
  Event              []EventTrigger              `xml:"EventTrigger,omitempty"`
  Idle               []IdleTrigger               `xml:"IdleTrigger,omitempty"`
  Logon              []LogonTrigger              `xml:"LogonTrigger,omitempty"`
  Registration       []RegistrationTrigger       `xml:"RegistrationTrigger,omitempty"`
  SessionStateChange []SessionStateChangeTrigger `xml:"SessionStateChangeTrigger,omitempty"`
}

// Repetition corresponds to the <Repetition> element (repetitionType),
// defining how often and for how long a trigger will re‑fire.  
type Repetition struct {
  XMLName           xml.Name `xml:"Repetition"`
  Interval          string   `xml:"Interval"`                    // duration, e.g. PT5M
  StopAtDurationEnd bool     `xml:"StopAtDurationEnd,omitempty"` // default=false
  Duration          string   `xml:"Duration,omitempty"`          // duration, max span
}

// BootTrigger starts a task when the system boots.  
// Inherits StartBoundary, EndBoundary, Enabled, Repetition, ExecutionTimeLimit.  
type BootTrigger struct {
  XMLName            xml.Name    `xml:"BootTrigger"`
  Id                 string      `xml:"id,attr,omitempty"`
  StartBoundary      string      `xml:"StartBoundary"`
  EndBoundary        string      `xml:"EndBoundary,omitempty"`
  Enabled            bool        `xml:"Enabled,omitempty"`
  Repetition         *Repetition `xml:"Repetition,omitempty"`
  ExecutionTimeLimit string      `xml:"ExecutionTimeLimit,omitempty"`
  Delay              string      `xml:"Delay,omitempty"` // duration after boot
}

// TimeTrigger fires once at a given time.  
// Adds RandomDelay to the base trigger.  
type TimeTrigger struct {
  XMLName            xml.Name    `xml:"TimeTrigger"`
  Id                 string      `xml:"id,attr,omitempty"`
  StartBoundary      string      `xml:"StartBoundary"`
  EndBoundary        string      `xml:"EndBoundary,omitempty"`
  Enabled            bool        `xml:"Enabled,omitempty"`
  Repetition         *Repetition `xml:"Repetition,omitempty"`
  ExecutionTimeLimit string      `xml:"ExecutionTimeLimit,omitempty"`
  RandomDelay        string      `xml:"RandomDelay,omitempty"` // optional jitter
}

// CalendarTrigger covers daily, weekly, monthly & DOW schedules.  
type CalendarTrigger struct {
  XMLName                  xml.Name            `xml:"CalendarTrigger"`
  Id                       string              `xml:"id,attr,omitempty"`
  StartBoundary            string              `xml:"StartBoundary"`
  EndBoundary              string              `xml:"EndBoundary,omitempty"`
  Enabled                  bool                `xml:"Enabled,omitempty"`
  Repetition               *Repetition         `xml:"Repetition,omitempty"`
  ExecutionTimeLimit       string              `xml:"ExecutionTimeLimit,omitempty"`
  RandomDelay              string              `xml:"RandomDelay,omitempty"`
  ScheduleByDay            *DailySchedule      `xml:"ScheduleByDay,omitempty"`
  ScheduleByWeek           *WeeklySchedule     `xml:"ScheduleByWeek,omitempty"`
  ScheduleByMonth          *MonthlySchedule    `xml:"ScheduleByMonth,omitempty"`
  ScheduleByMonthDayOfWeek *MonthlyDOWSchedule `xml:"ScheduleByMonthDayOfWeek,omitempty"`
}

// Support types for CalendarTrigger:

// DailySchedule (dailyScheduleType): interval in days.
type DailySchedule struct {
  DaysInterval int `xml:"DaysInterval,omitempty"`
}

// WeeklySchedule (weeklyScheduleType): weeks interval + days flag.
type WeeklySchedule struct {
  WeeksInterval int         `xml:"WeeksInterval,omitempty"`
  DaysOfWeek    *DaysOfWeek `xml:"DaysOfWeek,omitempty"`
}

// MonthlySchedule (monthlyScheduleType): specific month days + months.
type MonthlySchedule struct {
  DaysOfMonth *DaysOfMonth `xml:"DaysOfMonth,omitempty"`
  Months      *Months      `xml:"Months,omitempty"`
}

// MonthlyDOWSchedule (monthlyDayOfWeekScheduleType): weeks of month + days + months.
type MonthlyDOWSchedule struct {
  Weeks      *Weeks     `xml:"Weeks,omitempty"`
  DaysOfWeek DaysOfWeek `xml:"DaysOfWeek"`
  Months     *Months    `xml:"Months,omitempty"`
}

// DaysOfWeek (daysOfWeekType): a set of empty elements indicating which weekdays.
type DaysOfWeek struct {
  Monday    *struct{} `xml:"Monday,omitempty"`
  Tuesday   *struct{} `xml:"Tuesday,omitempty"`
  Wednesday *struct{} `xml:"Wednesday,omitempty"`
  Thursday  *struct{} `xml:"Thursday,omitempty"`
  Friday    *struct{} `xml:"Friday,omitempty"`
  Saturday  *struct{} `xml:"Saturday,omitempty"`
  Sunday    *struct{} `xml:"Sunday,omitempty"`
}

// DaysOfMonth (daysOfMonthType): list of numeric days in a month.
type DaysOfMonth struct {
  Day []int `xml:"Day,omitempty"`
}

// Months (monthsType): empty elements for each month.
type Months struct {
  January   *struct{} `xml:"January,omitempty"`
  February  *struct{} `xml:"February,omitempty"`
  March     *struct{} `xml:"March,omitempty"`
  April     *struct{} `xml:"April,omitempty"`
  May       *struct{} `xml:"May,omitempty"`
  June      *struct{} `xml:"June,omitempty"`
  July      *struct{} `xml:"July,omitempty"`
  August    *struct{} `xml:"August,omitempty"`
  September *struct{} `xml:"September,omitempty"`
  October   *struct{} `xml:"October,omitempty"`
  November  *struct{} `xml:"November,omitempty"`
  December  *struct{} `xml:"December,omitempty"`
}

// Weeks (weeksType): list of "1"–"4" or "Last".
type Weeks struct {
  Week []string `xml:"Week,omitempty"`
}

// EventTrigger fires on matching Windows events.  
type EventTrigger struct {
  XMLName            xml.Name     `xml:"EventTrigger"`
  Id                 string       `xml:"id,attr,omitempty"`
  StartBoundary      string       `xml:"StartBoundary,omitempty"`
  EndBoundary        string       `xml:"EndBoundary,omitempty"`
  Enabled            bool         `xml:"Enabled,omitempty"`
  Repetition         *Repetition  `xml:"Repetition,omitempty"`
  ExecutionTimeLimit string       `xml:"ExecutionTimeLimit,omitempty"`
  Subscription       string       `xml:"Subscription"` // XPath query
  Delay              string       `xml:"Delay,omitempty"`
  ValueQueries       *NamedValues `xml:"ValueQueries,omitempty"`
}

// IdleTrigger fires when the system goes idle.  
type IdleTrigger struct {
  XMLName            xml.Name    `xml:"IdleTrigger"`
  Id                 string      `xml:"id,attr,omitempty"`
  StartBoundary      string      `xml:"StartBoundary"`
  EndBoundary        string      `xml:"EndBoundary,omitempty"`
  Enabled            bool        `xml:"Enabled,omitempty"`
  Repetition         *Repetition `xml:"Repetition,omitempty"`
  ExecutionTimeLimit string      `xml:"ExecutionTimeLimit,omitempty"`
}

// LogonTrigger fires on user logon (optionally scoped by UserId).  
type LogonTrigger struct {
  XMLName            xml.Name    `xml:"LogonTrigger"`
  Id                 string      `xml:"id,attr,omitempty"`
  StartBoundary      string      `xml:"StartBoundary"`
  EndBoundary        string      `xml:"EndBoundary,omitempty"`
  Enabled            bool        `xml:"Enabled,omitempty"`
  Repetition         *Repetition `xml:"Repetition,omitempty"`
  ExecutionTimeLimit string      `xml:"ExecutionTimeLimit,omitempty"`
  UserId             string      `xml:"UserId,omitempty"`
  Delay              string      `xml:"Delay,omitempty"`
}

// RegistrationTrigger fires when the task is registered or updated.  
type RegistrationTrigger struct {
  XMLName            xml.Name    `xml:"RegistrationTrigger"`
  Id                 string      `xml:"id,attr,omitempty"`
  StartBoundary      string      `xml:"StartBoundary"`
  EndBoundary        string      `xml:"EndBoundary,omitempty"`
  Enabled            bool        `xml:"Enabled,omitempty"`
  Repetition         *Repetition `xml:"Repetition,omitempty"`
  ExecutionTimeLimit string      `xml:"ExecutionTimeLimit,omitempty"`
  Delay              string      `xml:"Delay,omitempty"`
}

// SessionStateChangeTrigger fires on terminal‑server session changes.  
type SessionStateChangeTrigger struct {
  XMLName            xml.Name    `xml:"SessionStateChangeTrigger"`
  Id                 string      `xml:"id,attr,omitempty"`
  StartBoundary      string      `xml:"StartBoundary,omitempty"`
  EndBoundary        string      `xml:"EndBoundary,omitempty"`
  Enabled            bool        `xml:"Enabled,omitempty"`
  Repetition         *Repetition `xml:"Repetition,omitempty"`
  ExecutionTimeLimit string      `xml:"ExecutionTimeLimit,omitempty"`
  StateChange        string      `xml:"StateChange"` // e.g. “Connect” or “Disconnect”
  UserId             string      `xml:"UserId,omitempty"`
  Delay              string      `xml:"Delay,omitempty"`
}
