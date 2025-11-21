import './FilePreview.css'

const FilePreview = ({ file, onRemove }) => {
  const getFileIcon = () => {
    const type = file.type.split('/')[0]
    switch (type) {
      case 'image':
        return 'fa-file-image'
      case 'video':
        return 'fa-file-video'
      case 'audio':
        return 'fa-file-audio'
      case 'application':
        if (file.type.includes('pdf')) return 'fa-file-pdf'
        if (file.type.includes('zip')) return 'fa-file-archive'
        if (file.type.includes('word')) return 'fa-file-word'
        if (file.type.includes('excel')) return 'fa-file-excel'
        if (file.type.includes('powerpoint')) return 'fa-file-powerpoint'
        return 'fa-file'
      default:
        return 'fa-file'
    }
  }

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
  }

  const isImage = file.type.startsWith('image/')
  const previewUrl = isImage ? URL.createObjectURL(file) : null

  return (
    <div className="file-preview">
      <div className="file-preview-content">
        <div className="file-info">
          {isImage ? (
            <div
              className="file-thumbnail"
              style={{ backgroundImage: `url(${previewUrl})` }}
            />
          ) : (
            <div className="file-icon">
              <i className={`fas ${getFileIcon()}`}></i>
            </div>
          )}
          
          <div className="file-details">
            <span className="file-name">{file.name}</span>
            <span className="file-size">{formatFileSize(file.size)}</span>
          </div>
        </div>

        <button className="remove-btn" onClick={onRemove}>
          <i className="fas fa-times"></i>
        </button>
      </div>
    </div>
  )
}

export default FilePreview
