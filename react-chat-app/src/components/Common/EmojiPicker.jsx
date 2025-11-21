import { useState } from 'react'
import './EmojiPicker.css'

const EmojiPicker = ({ onSelect, onClose }) => {
  const [activeCategory, setActiveCategory] = useState('smileys')

  const emojiCategories = {
    smileys: {
      icon: '😊',
      name: 'Smileys & People',
      emojis: [
        '😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😂',
        '🙂', '🙃', '😉', '😊', '😇', '🥰', '😍', '🤩',
        '😘', '😗', '😚', '😙', '🥲', '😋', '😛', '😜',
        '🤪', '😝', '🤑', '🤗', '🤭', '🤫', '🤔', '🤐',
      ],
    },
    nature: {
      icon: '🌿',
      name: 'Animals & Nature',
      emojis: [
        '🐶', '🐱', '🐭', '🐹', '🐰', '🦊', '🐻', '🐼',
        '🐨', '🐯', '🦁', '🐮', '🐷', '🐸', '🐵', '🐔',
        '🌸', '🌺', '🌻', '🌷', '🌹', '🌼', '🌿', '🍀',
        '🌲', '🌳', '🌴', '🌵', '🌾', '🌱', '☘️', '🍃',
      ],
    },
    food: {
      icon: '🍕',
      name: 'Food & Drink',
      emojis: [
        '🍎', '🍊', '🍋', '🍌', '🍉', '🍇', '🍓', '🍈',
        '🍒', '🍑', '🥭', '🍍', '🥥', '🥝', '🍅', '🥑',
        '🍕', '🍔', '🌭', '🥪', '🌮', '🌯', '🥙', '🥗',
        '🍜', '🍝', '🍛', '🍣', '🍱', '🍙', '🍚', '🍘',
      ],
    },
    activities: {
      icon: '⚽',
      name: 'Activities',
      emojis: [
        '⚽', '🏀', '🏈', '⚾', '🥎', '🎾', '🏐', '🏉',
        '🥏', '🎱', '🪀', '🏓', '🏸', '🏒', '🏑', '🥍',
        '🎮', '🕹️', '🎲', '🎯', '🎳', '🎪', '🎨', '🎬',
        '🎭', '🎤', '🎧', '🎼', '🎹', '🥁', '🎷', '🎺',
      ],
    },
    travel: {
      icon: '✈️',
      name: 'Travel & Places',
      emojis: [
        '🚗', '🚕', '🚙', '🚌', '🚎', '🏎️', '🚓', '🚑',
        '🚒', '🚐', '🛻', '🚚', '🚛', '🚜', '🏍️', '🛵',
        '✈️', '🚁', '🚂', '🚆', '🚊', '🚝', '🚞', '🚋',
        '🏠', '🏡', '🏢', '🏣', '🏤', '🏥', '🏦', '🏨',
      ],
    },
    objects: {
      icon: '💡',
      name: 'Objects',
      emojis: [
        '⌚', '📱', '📲', '💻', '⌨️', '🖥️', '🖨️', '🖱️',
        '🖲️', '🕹️', '💽', '💾', '💿', '📀', '📼', '📷',
        '💡', '🔦', '🕯️', '🪔', '🔌', '🔋', '📡', '💎',
        '🔨', '🪛', '🔧', '🔩', '⚙️', '🧰', '🪚', '⚒️',
      ],
    },
    symbols: {
      icon: '❤️',
      name: 'Symbols',
      emojis: [
        '❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍',
        '🤎', '💔', '❣️', '💕', '💞', '💓', '💗', '💖',
        '⭐', '🌟', '✨', '💫', '⚡', '🔥', '💥', '💦',
        '✅', '❌', '⭕', '🚫', '💯', '🔴', '🟠', '🟡',
      ],
    },
    flags: {
      icon: '🏁',
      name: 'Flags',
      emojis: [
        '🏁', '🚩', '🎌', '🏴', '🏳️', '🏳️‍🌈', '🏴‍☠️', '🇺🇳',
        '🇺🇸', '🇬🇧', '🇨🇦', '🇦🇺', '🇩🇪', '🇫🇷', '🇪🇸', '🇮🇹',
        '🇯🇵', '🇰🇷', '🇨🇳', '🇮🇳', '🇧🇷', '🇲🇽', '🇷🇺', '🇿🇦',
      ],
    },
  }

  return (
    <>
      <div className="emoji-picker-overlay" onClick={onClose} />
      <div className="emoji-picker">
        <div className="emoji-picker-header">
          <h3>Select Emoji</h3>
          <button className="close-btn" onClick={onClose}>
            <i className="fas fa-times"></i>
          </button>
        </div>

        <div className="emoji-categories">
          {Object.entries(emojiCategories).map(([key, category]) => (
            <button
              key={key}
              className={`category-btn ${
                activeCategory === key ? 'active' : ''
              }`}
              onClick={() => setActiveCategory(key)}
              title={category.name}
            >
              {category.icon}
            </button>
          ))}
        </div>

        <div className="emoji-grid">
          {emojiCategories[activeCategory].emojis.map((emoji, index) => (
            <button
              key={index}
              className="emoji-btn"
              onClick={() => {
                onSelect(emoji)
                onClose()
              }}
            >
              {emoji}
            </button>
          ))}
        </div>
      </div>
    </>
  )
}

export default EmojiPicker
