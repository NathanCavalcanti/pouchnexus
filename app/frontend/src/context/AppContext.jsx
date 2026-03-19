import { createContext, useContext, useState, useEffect } from 'react'
import { translations } from './Translations'

const AppContext = createContext()

export function AppProvider({ children }) {
  // Persistence using LocaleStorage
  const [lang, setLang] = useState(localStorage.getItem('lang') || 'en')
  
  // High-level settings for state persistence
  const [pref, setPref] = useState(() => {
    const saved = localStorage.getItem('userPreferences')
    return saved ? JSON.parse(saved) : { refreshInterval: 15000, theme: 'dark' }
  })

  useEffect(() => {
    localStorage.setItem('lang', lang)
  }, [lang])

  useEffect(() => {
    localStorage.setItem('userPreferences', JSON.stringify(pref))
  }, [pref])

  const t = translations[lang] || translations['en']

  // Helper function to update specific settings without losing others
  const updatePref = (key, value) => {
    setPref(prev => ({ ...prev, [key]: value }))
  }

  return (
    <AppContext.Provider value={{ lang, setLang, t, pref, updatePref }}>
      {children}
    </AppContext.Provider>
  )
}

export const useApp = () => useContext(AppContext)
