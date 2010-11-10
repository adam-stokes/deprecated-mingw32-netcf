/*
 * dutil.c: Global utility functions for driver backends.
 *
 * Copyright (C) 2009 Red Hat Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: David Lutterkort <lutter@redhat.com>
 */

#include <config.h>
#include <internal.h>

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include <libxml/parser.h>
#include <libxml/relaxng.h>
#include <libxml/tree.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>

/* Like asprintf, but set *STRP to NULL on error */
int xasprintf(char **strp, const char *format, ...) {
  va_list args;
  int result;

  va_start (args, format);
  result = vasprintf (strp, format, args);
  va_end (args);
  if (result < 0)
      *strp = NULL;
  return result;
}

void free_matches(int nint, char ***intf) {
    if (*intf != NULL) {
        for (int i=0; i < nint; i++)
            FREE((*intf)[i]);
        FREE(*intf);
    }
}

xsltStylesheetPtr parse_stylesheet(struct netcf *ncf,
                                          const char *fname) {
    xsltStylesheetPtr result = NULL;
    char *path = NULL;
    int r;

    r = xasprintf(&path, "%s/xml/%s", ncf->data_dir, fname);
    ERR_NOMEM(r < 0, ncf);

    if (access(path, R_OK) < 0) {
        report_error(ncf, NETCF_EFILE,
                     "Stylesheet %s does not exist or is not readable",
                     path);
        goto error;
    }

    result = xsltParseStylesheetFile(BAD_CAST path);
    ERR_THROW(result == NULL, ncf, EFILE,
              "Could not parse stylesheet %s", path);

 error:
    free(path);
    return result;
}

ATTRIBUTE_FORMAT(printf, 2, 3)
static void apply_stylesheet_error(void *ctx, const char *format, ...) {
    struct netcf *ncf = ctx;
    va_list ap;

    va_start(ap, format);
    vreport_error(ncf, NETCF_EXSLTFAILED, format, ap);
    va_end(ap);
}

xmlDocPtr apply_stylesheet(struct netcf *ncf, xsltStylesheetPtr style,
                           xmlDocPtr doc) {
    xsltTransformContextPtr ctxt;
    xmlDocPtr res = NULL;
    int r;

    ctxt = xsltNewTransformContext(style, doc);
    ERR_NOMEM(ctxt == NULL, ncf);

    xsltSetTransformErrorFunc(ctxt, ncf, apply_stylesheet_error);

    r = xslt_register_exts(ctxt);
    ERR_NOMEM(r < 0, ncf);

    res = xsltApplyStylesheetUser(style, doc, NULL, NULL, NULL, ctxt);
    if ((ctxt->state == XSLT_STATE_ERROR) ||
        (ctxt->state == XSLT_STATE_STOPPED)) {
        xmlFreeDoc(res);
        res = NULL;
        /* Fallback, in case our error handler isn't called */
        report_error(ncf, NETCF_EXSLTFAILED, NULL);
    }

error:
    xsltFreeTransformContext(ctxt);
    return res;
}

char *apply_stylesheet_to_string(struct netcf *ncf, xsltStylesheetPtr style,
                                 xmlDocPtr doc) {
    xmlDocPtr doc_xfm = NULL;
    char *result = NULL;
    int r, result_len;

    doc_xfm = apply_stylesheet(ncf, style, doc);
    ERR_BAIL(ncf);

    r = xsltSaveResultToString((xmlChar **) &result, &result_len,
                               doc_xfm, style);
    ERR_NOMEM(r < 0, ncf);
    xmlFreeDoc(doc_xfm);
    return result;

 error:
    FREE(result);
    xmlFreeDoc(doc_xfm);
    return NULL;
}

/* Callback for reporting RelaxNG errors */
void rng_error(void *ctx, const char *format, ...) {
    struct netcf *ncf = ctx;
    va_list ap;

    va_start(ap, format);
    vreport_error(ncf, NETCF_EXMLINVALID, format, ap);
    va_end(ap);
}

xmlRelaxNGPtr rng_parse(struct netcf *ncf, const char *fname) {
    char *path = NULL;
    xmlRelaxNGPtr result = NULL;
    xmlRelaxNGParserCtxtPtr ctxt = NULL;
    int r;

    r = xasprintf(&path, "%s/xml/%s", ncf->data_dir, fname);
    ERR_NOMEM(r < 0, ncf);

    if (access(path, R_OK) < 0) {
        report_error(ncf, NETCF_EFILE,
                     "File %s does not exist or is not readable", path);
        goto error;
    }

    ctxt = xmlRelaxNGNewParserCtxt(path);
    xmlRelaxNGSetParserErrors(ctxt, rng_error, rng_error, ncf);

    result = xmlRelaxNGParse(ctxt);

 error:
    xmlRelaxNGFreeParserCtxt(ctxt);
    free(path);
    return result;
}

void rng_validate(struct netcf *ncf, xmlDocPtr doc) {
	xmlRelaxNGValidCtxtPtr ctxt;
	int r;

	ctxt = xmlRelaxNGNewValidCtxt(ncf->driver->rng);
	xmlRelaxNGSetValidErrors(ctxt, rng_error, rng_error, ncf);

    r = xmlRelaxNGValidateDoc(ctxt, doc);
    if (r != 0 && ncf->errcode == NETCF_NOERROR)
        report_error(ncf, NETCF_EXMLINVALID,
           "Interface definition fails to validate");

	xmlRelaxNGFreeValidCtxt(ctxt);
}

/* Called from SAX on parsing errors in the XML. */
void catch_xml_error(void *ctx, const char *msg ATTRIBUTE_UNUSED, ...) {
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

    if (ctxt != NULL) {
        struct netcf *ncf = ctxt->_private;

        if (ctxt->lastError.level == XML_ERR_FATAL &&
            ctxt->lastError.message != NULL) {
            report_error(ncf, NETCF_EXMLPARSER,
                         "at line %d: %s",
                         ctxt->lastError.line,
                         ctxt->lastError.message);
        }
    }
}

xmlDocPtr parse_xml(struct netcf *ncf, const char *xml_str) {
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt();
    ERR_NOMEM(pctxt == NULL || pctxt->sax == NULL, ncf);

    pctxt->sax->error = catch_xml_error;
    pctxt->_private = ncf;

    xml = xmlCtxtReadDoc (pctxt, BAD_CAST xml_str, "netcf.xml", NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOWARNING);
    ERR_THROW(xml == NULL, ncf, EXMLPARSER,
              "failed to parse xml document");
    ERR_THROW(xmlDocGetRootElement(xml) == NULL, ncf, EINTERNAL,
              "missing root element");

    xmlFreeParserCtxt(pctxt);
    return xml;
error:
    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc (xml);
    return NULL;
}

char *xml_prop(xmlNodePtr node, const char *name) {
    return (char *) xmlGetProp(node, BAD_CAST name);
}

/* Create a new node and link it into the document, even if one of the
 * same name already exists. A NULL return means there was a memory
 * failure, and it needs to be reported by the caller.
 */
static xmlNodePtr xml_new_node(xmlDocPtr doc,
                               xmlNodePtr parent, const char *name) {
    xmlNodePtr cur, ret = NULL;

    ret = xmlNewDocNode(doc, NULL, BAD_CAST name, NULL);
    if (ret != NULL) {
        cur = xmlAddChild(parent, ret);
        if (cur == NULL) {
            xmlFreeNode(ret);
            ret = NULL;
        }
    }
    return ret;
}

/* Find existing node of given name within parent, or create and link
 * in a new one if not found.
 */
static xmlNodePtr xml_node(xmlDocPtr doc,
                           xmlNodePtr parent, const char *name) {
    xmlNodePtr cur, ret = NULL;

    for (cur = parent->children; cur != NULL; cur = cur->next) {
        if ((cur->type == XML_ELEMENT_NODE)
            && xmlStrEqual(cur->name, BAD_CAST name)) {
            ret = cur;
            break;
        }
    }
    if (ret == NULL) {
        /* node not found, create a new one */
        ret = xml_new_node(doc, parent, name);
    }
    return ret;
}

int init_ioctl_fd(struct netcf *ncf) {
    int ioctl_fd;
    int flags;

    ioctl_fd = socket(AF_INET, SOCK_STREAM, 0);
    ERR_THROW(ioctl_fd < 0, ncf, EINTERNAL, "failed to open socket for interface ioctl");

    flags = fcntl(ioctl_fd, F_GETFD);
    ERR_THROW(flags < 0, ncf, EINTERNAL, "failed to get flags for ioctl socket");

    flags = fcntl(ioctl_fd, F_SETFD, flags | FD_CLOEXEC);
    ERR_THROW(flags < 0, ncf, EINTERNAL, "failed to set FD_CLOEXEC flag on ioctl socket");
    return ioctl_fd;

error:
    if (ioctl_fd >= 0)
        close(ioctl_fd);
    return -1;
}

/* Create a new netcf if instance for interface NAME */
struct netcf_if *make_netcf_if(struct netcf *ncf, char *name) {
    int r;
    struct netcf_if *result = NULL;

    r = make_ref(result);
    ERR_NOMEM(r < 0, ncf);
    result->ncf = ref(ncf);
    result->name = name;
    return result;

 error:
    unref(result, netcf_if);
    return result;
}

void add_state_to_xml_doc(struct netcf_if *nif, xmlDocPtr doc) {
    xmlNodePtr root;
    int ifindex, code;

    root = xmlDocGetRootElement(doc);
    ERR_THROW((root == NULL), nif->ncf, EINTERNAL,
              "failed to get document root element");
    ERR_THROW(!xmlStrEqual(root->name, BAD_CAST "interface"),
              nif->ncf, EINTERNAL, "root document is not an interface");

    /* Update the caches with any recent changes */
    code = nl_cache_refill(nif->ncf->driver->nl_sock,
                           nif->ncf->driver->link_cache);
    ERR_THROW((code < 0), nif->ncf, ENETLINK,
              "failed to refill interface index cache");
    code = nl_cache_refill(nif->ncf->driver->nl_sock,
                           nif->ncf->driver->addr_cache);
    ERR_THROW((code < 0), nif->ncf, ENETLINK,
              "failed to refill interface address cache");

    ifindex = rtnl_link_name2i(nif->ncf->driver->link_cache, nif->name);
    ERR_THROW((ifindex == RTNL_LINK_NOT_FOUND), nif->ncf, ENETLINK,
              "couldn't find ifindex for interface `%s`", nif->name);

    add_type_specific_info(nif->ncf, nif->name, ifindex, doc, root);
    ERR_BAIL(nif->ncf);

    add_ip_info(nif->ncf, nif->name, ifindex, doc, root);
    ERR_BAIL(nif->ncf);

error:
    return;
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
/* vim: set ts=4 sw=4 et: */
