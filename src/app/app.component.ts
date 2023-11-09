import { Component } from '@angular/core';
import {
  HttpClient,
  HttpClientModule,
  HttpHeaders,
} from '@angular/common/http';
import { ActivatedRoute, Router } from '@angular/router';
import { map, tap } from 'rxjs';

function sha256(plain: string) {
  // returns promise ArrayBuffer
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  return window.crypto.subtle.digest('SHA-256', data);
}

function base64urlencode(a: ArrayBuffer) {
  // Convert the ArrayBuffer to string using Uint8 array.
  // btoa takes chars from 0-255 and base64 encodes.
  // Then convert the base64 encoded to base64url encoded.
  // (replace + with -, replace / with _, trim trailing =)
  return btoa(String.fromCharCode.apply(null, new Uint8Array(a) as any))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function pkce_challenge_from_verifier(v: string) {
  let hashed = await sha256(v);
  let base64encoded = base64urlencode(hashed);
  return base64encoded;
}

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss'],
})
export class AppComponent {
  title = 'zalo-test';

  state = '';
  code_verifier = '';
  app_id = '';
  secret_key = '';
  code_challenge: string = '';

  accessTokenData: any;

  queryParams: any = {};
  param$ = this.route.queryParamMap.pipe(
    map((data: any) => {
      this.queryParams = data['params'];
      return this.queryParams;
    })
  );

  constructor(
    private http: HttpClient,
    private route: ActivatedRoute,
    private router: Router
  ) {
    const data = localStorage.getItem('DATA');
    if (data) {
      const { state, code_verifier, app_id, secret_key } = JSON.parse(data);

      this.state = state;
      this.code_verifier = code_verifier;
      this.app_id = app_id;
      this.secret_key = secret_key;
    }
  }

  async login() {
    const redirect_uri = 'https://zalotest.vercel.app/';

    if (this.code_verifier && this.app_id) {
      this.code_challenge = await pkce_challenge_from_verifier(
        this.code_verifier
      );

      localStorage.setItem(
        'DATA',
        JSON.stringify({
          state: this.state,
          code_verifier: this.code_verifier,
          app_id: this.app_id,
          secret_key: this.secret_key,
        })
      );

      window.open(
        `https://oauth.zaloapp.com/v4/permission?app_id=${this.app_id}&redirect_uri=${redirect_uri}&code_challenge=${this.code_challenge}&state=${this.state}`,
        '_self'
      );
    }
  }

  signIn2() {
    fetch('https://oauth.zaloapp.com/v4/access_token', {
      method: 'POST',
      headers: {
        secret_key: this.secret_key,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        code: this.queryParams.code,
        app_id: this.app_id,
        grant_type: 'authorization_code',
        code_verifier: this.code_verifier,
      }),
    })
      .then((r) => r.json())
      .then((data) => {
        if (data) {
          localStorage.setItem('TOKEN', JSON.stringify(data));
        }
        this.accessTokenData = data;
      });
  }

  signIn() {
    const headers = new HttpHeaders();

    headers.append('Content-Type', 'application/x-www-form-urlencoded');
    headers.append('secret_key', this.secret_key);

    const formData = new FormData();

    formData.append('code', this.queryParams.code);
    formData.append('app_id', this.app_id);
    formData.append('grant_type', 'authorization_code');
    formData.append('code_verifier', this.code_verifier);

    this.http
      .post('https://oauth.zaloapp.com/v4/access_token', formData, {
        headers,
      })
      .subscribe({
        next: (data) => {
          this.accessTokenData = data;
          if (data) {
            localStorage.setItem('TOKEN', JSON.stringify(data));
          }
        },
        error: (errr) => {
          console.log(errr);
        },
      });
  }

  clearAll(isLogout = false) {
    if (isLogout) {
      localStorage.removeItem('TOKEN');
    } else {
      localStorage.clear();
    }

    this.router.navigate(['.'], { relativeTo: this.route });
  }
  getUser(accessToken: string) {
    let access_token = accessToken;
    if (accessToken == undefined) {
      const token = localStorage.getItem('TOKEN');

      const { access_token: aToken } = token
        ? JSON.parse(token)
        : { access_token };

      access_token = aToken;
    }

    const headers = new HttpHeaders();

    headers.append('access_token', access_token);

    this.http
      .get('https://graph.zalo.me/v2.0/me', { headers })
      .subscribe((data) => {
        console.log(data);
      });
  }
}
