package logout

import "time"

type sessionData struct {
	TokenExp     time.Time
	LastActivity time.Time
}

func ActivityMiddleware()  {
	
}
