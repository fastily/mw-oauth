package fastily.mwoauth;

import java.io.IOException;
import java.net.URLDecoder;

import com.github.scribejava.core.model.OAuth1AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth10aService;

import okhttp3.Headers;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okio.Buffer;

/**
 * An OkHttp Interceptor that lets you use OkHttp instead of Scribe to sign and send your requests.
 * 
 * @author Fastily
 *
 */
public class MWOAuthInterceptor implements Interceptor
{
	/**
	 * The oauth access token to use
	 */
	private OAuth1AccessToken accessToken;

	/**
	 * The OAuth service to sign requests with.
	 */
	private OAuth10aService service;

	/**
	 * Constructor, creates a new MWOAuthInterceptor.
	 * 
	 * @param service The service to sign requests with
	 * @param accessToken The access token from completing the OAuth authentication process.
	 */
	public MWOAuthInterceptor(OAuth10aService service, OAuth1AccessToken accessToken)
	{
		this.service = service;
		this.accessToken = accessToken;
	}

	/**
	 * Signs OAuth requests. Also supports multipart POSTing.
	 */
	public Response intercept(Chain chain) throws IOException
	{
		Request r = chain.request();

		OAuthRequest oauthReq = new OAuthRequest(Verb.valueOf(r.method()), r.url().toString());
		r.headers().toMultimap().forEach((k, v) -> v.forEach(s -> oauthReq.addHeader(k, s)));

		RequestBody rb;
		if (r.method().equals("POST") && !(rb = r.body()).contentType().toString().contains("multipart"))
		{
			Buffer b = new Buffer();
			rb.writeTo(b);

			for (String pair : new String(b.readByteArray()).split("&"))
			{
				String[] a = pair.split("=");
				oauthReq.addBodyParameter(a[0], a.length == 1 ? "" : URLDecoder.decode(a[1], "UTF-8"));
			}
		}

		service.signRequest(accessToken, oauthReq);

		return chain.proceed(r.newBuilder().headers(Headers.of(oauthReq.getHeaders())).build());
	}
}