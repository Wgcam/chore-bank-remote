import {Links,Meta,Outlet,Scripts,ScrollRestoration} from 'react-router';
import './style.css';
export default function Root(){return <html lang="en"><head><meta charSet="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>ChoreBank · Your family bank</title><Meta/><Links/></head><body><Outlet/><ScrollRestoration/><Scripts/></body></html>}
