function CopyToClipboard(id) {
  var r = document.createRange()
  r.selectNode(document.getElementById(id))
  window.getSelection().removeAllRanges()
  window.getSelection().addRange(r)
  document.execCommand('copy')
  window.getSelection().removeAllRanges()
}

$(document).ready(function () {
  $('#depositBtn').prop('disabled', true)
  $('#withdrawBtn').prop('disabled', true)
})
