import { useMemo } from 'react'

/**
 * A deliberately small markdown renderer.
 *
 * It handles the subset used in labs.meta.yaml: headings, bullet lists, fenced code
 * blocks, inline code, bold and paragraphs. It escapes everything first, so no user
 * content can inject markup - the lab content itself is trusted, but the same rule
 * keeps the renderer safe.
 */
export default function Markdown({ source }) {
  const blocks = useMemo(() => parse(source ?? ''), [source])

  return (
    <div className="markdown">
      {blocks.map((block, index) => {
        if (block.type === 'code') {
          return (
            <pre key={index} className="code-block">
              <code>{block.content}</code>
            </pre>
          )
        }
        if (block.type === 'heading') {
          return (
            <h3 key={index} className="md-heading">
              {inline(block.content)}
            </h3>
          )
        }
        if (block.type === 'list') {
          return (
            <ol key={index} className="md-list">
              {block.items.map((item, itemIndex) => (
                <li key={itemIndex}>{inline(item)}</li>
              ))}
            </ol>
          )
        }
        return (
          <p key={index} className="md-p">
            {inline(block.content)}
          </p>
        )
      })}
    </div>
  )
}

function parse(source) {
  const lines = source.split('\n')
  const blocks = []
  let index = 0

  while (index < lines.length) {
    const line = lines[index]

    if (line.trim().startsWith('```')) {
      const content = []
      index++
      while (index < lines.length && !lines[index].trim().startsWith('```')) {
        content.push(lines[index])
        index++
      }
      index++
      blocks.push({ type: 'code', content: content.join('\n') })
      continue
    }

    if (line.trim().startsWith('#')) {
      blocks.push({ type: 'heading', content: line.replace(/^#+\s*/, '') })
      index++
      continue
    }

    if (/^\s*(\d+\.|-|\*)\s+/.test(line)) {
      const items = []
      while (index < lines.length && /^\s*(\d+\.|-|\*)\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^\s*(\d+\.|-|\*)\s+/, ''))
        index++
      }
      blocks.push({ type: 'list', items })
      continue
    }

    if (line.trim() === '') {
      index++
      continue
    }

    const paragraph = []
    while (index < lines.length && lines[index].trim() !== '' &&
           !lines[index].trim().startsWith('```') &&
           !lines[index].trim().startsWith('#') &&
           !/^\s*(\d+\.|-|\*)\s+/.test(lines[index])) {
      paragraph.push(lines[index])
      index++
    }
    blocks.push({ type: 'paragraph', content: paragraph.join(' ') })
  }

  return blocks
}

/**
 * Renders inline markdown (bold, inline code) as React elements.
 */
function inline(text) {
  const parts = []
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`)/g
  let lastIndex = 0
  let match

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index))
    }
    const token = match[0]
    if (token.startsWith('**')) {
      parts.push(<strong key={match.index}>{token.slice(2, -2)}</strong>)
    } else {
      parts.push(
        <code key={match.index} className="inline-code">
          {token.slice(1, -1)}
        </code>,
      )
    }
    lastIndex = match.index + token.length
  }

  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex))
  }

  return parts
}
