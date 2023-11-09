import { Component } from '@angular/core';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { ActivatedRoute } from '@angular/router';
import { tap } from 'rxjs';

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

  queryParams: any = {};
  param$ = this.route.queryParamMap.pipe(
    tap((data) => (this.queryParams = data))
  );

  constructor(private http: HttpClient, private route: ActivatedRoute) {}

  async login() {
    const redirect_uri = 'https://zalotest.vercel.app/';

    if (this.code_verifier && this.app_id) {
      const code_challenge = await pkce_challenge_from_verifier(
        this.code_verifier
      ).catch(console.log);

      window.open(
        `https://oauth.zaloapp.com/v4/permission?app_id=${this.app_id}&redirect_uri=${redirect_uri}&code_challenge=${code_challenge}&state=${this.state}`,
        '_self'
      );
    }
  }

  signIn() {
    this.http
      .post(
        'https://oauth.zaloapp.com/v4/access_token',
        {
          code: this.queryParams.code,
          app_id: this.app_id,
          grant_type: 'authorization',
          code_verifier: this.code_verifier,
        },
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }
      )
      .subscribe({
        next: (res) => {
          console.log(res);
        },
        error: (errr) => {
          console.log(errr);
        },
      });
  }
}
