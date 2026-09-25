const charSets = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()_+~`|}{[]:;?><,./-='
};

const lengthSlider = document.getElementById('length-slider');
const lengthVal = document.getElementById('length-val');
const chkUpper = document.getElementById('chk-upper');
const chkLower = document.getElementById('chk-lower');
const chkNumbers = document.getElementById('chk-numbers');
const chkSymbols = document.getElementById('chk-symbols');
const generateBtn = document.getElementById('generate-btn');
const passwordDisplay = document.getElementById('password-display');
const copyBtn = document.getElementById('copy-btn');
const iconCopy = document.getElementById('icon-copy');
const iconCheck = document.getElementById('icon-check');
const toggleVisibilityBtn = document.getElementById('toggle-visibility-btn');
const iconEye = document.getElementById('icon-eye');
const iconEyeSlash = document.getElementById('icon-eye-slash');
const visibilityText = document.getElementById('visibility-text');
const strengthBar = document.getElementById('strength-bar');
const strengthText = document.getElementById('strength-text');
const themeToggle = document.getElementById('theme-toggle');

let currentPassword = '';
let isMasked = false;

themeToggle.addEventListener('change', (e) => {
	if (e.target.checked) {
		document.body.classList.add('light-mode');
		localStorage.setItem('fortifyTheme', 'light'); 
	} else {
		document.body.classList.remove('light-mode');
		localStorage.setItem('fortifyTheme', 'dark');
	}
});

const savedTheme = localStorage.getItem('fortifyTheme');
if (savedTheme === 'light') {
	themeToggle.checked = true;
	document.body.classList.add('light-mode');
}

lengthSlider.addEventListener('input', (e) => {
  lengthVal.textContent = e.target.value;
});

function generatePassword() {
  const length = parseInt(lengthSlider.value);
  const hasUpper = chkUpper.checked;
  const hasLower = chkLower.checked;
  const hasNumbers = chkNumbers.checked;
  const hasSymbols = chkSymbols.checked;

  if (!hasUpper && !hasLower && !hasNumbers && !hasSymbols) {
	chkLower.checked = true;
	return generatePassword();
  }

  let availableChars = '';
  let guaranteedChars = '';

  if (hasUpper) { availableChars += charSets.upper; guaranteedChars += getRandomChar(charSets.upper); }
  if (hasLower) { availableChars += charSets.lower; guaranteedChars += getRandomChar(charSets.lower); }
  if (hasNumbers) { availableChars += charSets.numbers; guaranteedChars += getRandomChar(charSets.numbers); }
  if (hasSymbols) { availableChars += charSets.symbols; guaranteedChars += getRandomChar(charSets.symbols); }

  let generatedPassword = guaranteedChars;

  for (let i = guaranteedChars.length; i < length; i++) {
	generatedPassword += getRandomChar(availableChars);
  }

  currentPassword = shuffleString(generatedPassword);
  updatePasswordDisplay();
  updateStrengthIndicator(length, hasUpper, hasLower, hasNumbers, hasSymbols);
  resetCopyIcon();
}

function updatePasswordDisplay() {
  if (!currentPassword) {
	passwordDisplay.textContent = 'Click Generate';
	return;
  }
  passwordDisplay.textContent = isMasked ? '•'.repeat(currentPassword.length) : currentPassword;
  passwordDisplay.classList.remove('text-muted');
}

function getRandomChar(str) {
  const array = new Uint32Array(1);
  window.crypto.getRandomValues(array);
  return str[array[0] % str.length];
}

function shuffleString(str) {
  let arr = str.split('');
  for (let i = arr.length - 1; i > 0; i--) {
	const array = new Uint32Array(1);
	window.crypto.getRandomValues(array);
	const j = array[0] % (i + 1);
	[arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join('');
}

function updateStrengthIndicator(length, hasU, hasL, hasN, hasS) {
	let typeCount = (hasU?1:0) + (hasL?1:0) + (hasN?1:0) + (hasS?1:0);
	let strength = 'Weak'; let barClass = 'strength-weak'; let color = '#ef4444';

	if (length >= 16 && typeCount >= 3) { strength = 'Strong'; barClass = 'strength-strong'; color = '#4ade80'; }
	else if (length >= 12 && typeCount >= 2) { strength = 'Medium'; barClass = 'strength-medium'; color = '#facc15'; }

	strengthText.textContent = strength;
	strengthText.style.color = color;
	strengthBar.className = `strength-bar-fill ${barClass}`;
}

function copyToClipboard() {
  if (!currentPassword || currentPassword === 'Click Generate') return;
  
  const textarea = document.createElement('textarea');
  textarea.value = currentPassword;
  document.body.appendChild(textarea);
  textarea.select();
  
  try {
	document.execCommand('copy');
	showCopySuccess();
  } catch (err) {
	if (navigator.clipboard) {
	   navigator.clipboard.writeText(currentPassword).then(showCopySuccess);
	}
  } finally {
	document.body.removeChild(textarea);
  }
}

function showCopySuccess() {
	iconCopy.style.display = 'none';
	iconCheck.style.display = 'block';
	setTimeout(resetCopyIcon, 2000);
}

function resetCopyIcon() {
	iconCopy.style.display = 'block';
	iconCheck.style.display = 'none';
}

generateBtn.addEventListener('click', generatePassword);
copyBtn.addEventListener('click', copyToClipboard);

toggleVisibilityBtn.addEventListener('click', () => {
  isMasked = !isMasked;
  iconEye.style.display = isMasked ? 'none' : 'block';
  iconEyeSlash.style.display = isMasked ? 'block' : 'none';
  if (visibilityText) visibilityText.textContent = isMasked ? 'Show' : 'Hide';
  toggleVisibilityBtn.title = isMasked ? 'Show password' : 'Hide password';
  updatePasswordDisplay();
});

window.addEventListener('DOMContentLoaded', () => {
	lengthSlider.value = 24; 
	lengthVal.textContent = 24;
	generatePassword();
});