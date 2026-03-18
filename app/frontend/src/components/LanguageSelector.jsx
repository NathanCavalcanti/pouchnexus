import { useApp } from '../context/AppContext'
import { Globe } from 'lucide-react'

export default function LanguageSelector() {
  const { lang, setLang } = useApp()

  const languages = [
    { code: 'en', label: 'English', icon: '🇺🇸' },
    { code: 'es', label: 'Español', icon: '🇪🇸' },
    { code: 'de', label: 'Deutsch', icon: '🇩🇪' },
  ]

  return (
    <div className="language-selector">
      <Globe size={14} className="text-muted" />
      <select 
        value={lang} 
        onChange={(e) => setLang(e.target.value)}
        className="lang-select"
      >
        {languages.map(l => (
          <option key={l.code} value={l.code}>
            {l.icon} {l.label}
          </option>
        ))}
      </select>
    </div>
  )
}
