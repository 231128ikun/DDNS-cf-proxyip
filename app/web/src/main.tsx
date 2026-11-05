import { render } from 'preact';
import { AuthGate } from './auth-gate';
import { restoreTheme } from './state/theme';
import './styles.css';

const root = document.getElementById('app');
if (!root) throw new Error('missing #app root');

restoreTheme();
root.replaceChildren();
render(<AuthGate />, root);
