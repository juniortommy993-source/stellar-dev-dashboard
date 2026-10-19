import { AppRegistry, Platform } from 'react-native'
import App from './src/App'
import { name as appName } from './app.json'
import { setupBackgroundHandler } from './src/services/notifications'
import { redactWalletError, sanitizeWalletError } from './src/lib/wallet/redactWalletErrors'
import { setErrorRedactor } from './src/lib/errorTracking'

// Redact wallet-sensitive data before any error reaches telemetry or user export.
setErrorRedactor(redactWalletError)

// Global handlers for uncaught errors and unhandled promise rejections.
const defaultErrorHandler = ErrorUtils.getGlobalHandler()
ErrorUtils.setGlobalHandler((error, isFatal) => {
  const sanitized = sanitizeWalletError(error)
  defaultErrorHandler(sanitized, isFatal)
})

setupBackgroundHandler()

AppRegistry.registerComponent(appName, () => App)
