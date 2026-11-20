// Side-effect module imported first in main.js: it must run before the router module reads window.location,
// otherwise the router's initial navigation writes the #cr-token fragment back into the address bar.
import { captureLocalToken } from './api'

captureLocalToken()
