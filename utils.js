function CopyToClipboard(id) {
  var r = document.createRange()
  r.selectNode(document.getElementById(id))
  window.getSelection().removeAllRanges()
  window.getSelection().addRange(r)
  document.execCommand('copy')
  window.getSelection().removeAllRanges()
}

function Download(id) {
  var element = document.createElement('a')
  var text = document.getElementById(id).textContent
  element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text))
  element.setAttribute('download', 'secret-key-interstellar')

  element.style.display = 'none'
  document.body.appendChild(element)

  element.click()

  document.body.removeChild(element)
}

$(document).ready(function () {
  $('#depositBtn').prop('disabled', true)
  $('#withdrawBtn').prop('disabled', true)
})
