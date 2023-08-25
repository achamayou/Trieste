// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "source.h"

extern "C" {
#include <libregexp.h>
}

#include <string_view>
#include <charconv>

// Disclaimer: this is entirely untested and made up, and almost certainly explodes

namespace trieste
{
  class QJSRE
  {
    friend class QJSREMatch;

    private:
      const uint8_t* bytecode;
      int bytecode_size;

    public:
      QJSRE(const std::string& regex) {
        int error_msg_size = 64;
        char error_msg[64];
        
        int flags = LRE_FLAG_STICKY; // Same as RE2::ANCHOR_START
        bytecode = lre_compile(&bytecode_size,
                               error_msg,
                               error_msg_size,
                               regex.c_str(),
                               regex.size(),
                               flags,
                               nullptr);
        if (bytecode == nullptr) {
          throw std::runtime_error(error_msg);
        }
      }

      ~QJSRE() {
        free((void*)bytecode);
      }
  };

  class QJSREMatch
  {
    friend class QJSREIterator;

  private:
    std::vector<Location> locations;
    size_t matches = 0;
    uint8_t ** capture; // TODO: probably a vector of uint8_t* instead
    std::vector<std::string_view> match_svs; // TODO: this seems redundant with locations

  public:
    bool match_regexp(const QJSRE& regex, std::string_view& sp, Source& source)
    {
      size_t capture_count = lre_get_capture_count(regex.bytecode);
      capture = (uint8_t **) (sizeof(capture[0]) * capture_count * 2);
      const uint8_t* sp_data = reinterpret_cast<const uint8_t*>(sp.data());
      int matched_ = lre_exec(capture, regex.bytecode, sp_data, 0, sp.size(), 0, nullptr);
      if (matched_ < 0)
        throw std::logic_error("lre_exec failed");
      size_t matched = static_cast<size_t>(matched_);
      matches = matched;

      if (matched < locations.size())
      {
        locations.resize(matched);
      }
      if (matched < match_svs.size())
      {
        match_svs.resize(matched);
      }

      for (size_t i = 0; i < matched; i++)
      {
        // TODO: needs NULL checks here, the captures can be empty it seems
        const uint8_t* start = capture[i * 2];
        const uint8_t* end = capture[i * 2 + 1];
        locations[i] = {
          source,
          (size_t)((const char*)start - source->view().data()),
          (size_t)(end - start)};
        match_svs[i] = std::string_view((const char*)start, (const char*)end);
      }
      // TODO: How does RE2 work, and why is there a +1? Is it implicitly the whole string at the beginning/end?

      return matched > 0;
    }

    bool match(const std::string_view& sv, const QJSRE& regex)
    {
      const uint8_t* sv_data = reinterpret_cast<const uint8_t*>(sv.data());
      return lre_exec(capture, regex.bytecode, sv_data, 0, sv.size(), 0, nullptr);
    }

    QJSREMatch(size_t max_capture = 0)
    {
      locations.resize(max_capture);
      match_svs.resize(max_capture);
    }

    const Location& at(size_t index = 0) const
    {
      if (index >= matches)
        return locations.at(0);

      return locations.at(index);
    }

    template<typename T>
    T parse(size_t index = 0) const
    {
      if (index >= matches)
        return T();

      T t;
      auto& m = match_svs.at(index);
      std::from_chars(m.data(), m.data() + m.size(), t);
      return t;
    }
  };


  class QJSREIterator
  {
  private:
    Source source;
    std::string_view sp;

  public:
    QJSREIterator(Source source) : source(source), sp(source->view()) {}

    bool empty()
    {
      return sp.empty();
    }

    bool consume(const QJSRE& regex, QJSREMatch& m)
    {
      if (!m.match_regexp(regex, sp, source))
        return false;

      sp.remove_prefix(m.at(0).len);
      return true;
    }

    Location current() const
    {
      return {
        source, static_cast<size_t>(sp.data() - source->view().data()), 1};
    }

    void skip(size_t count = 1)
    {
      sp.remove_prefix(count);
    }
  };

  inline Node build_ast(Source source, size_t pos, std::ostream& out)
  {
    // TODO: convert space and digit to \s and \d probably but check they're really the same
    auto hd = QJSRE("[[:space:]]*\\([[:space:]]*([^[:space:]\\(\\)]*)");
    auto st = QJSRE("[[:space:]]*\\{[^\\}]*\\}");
    auto id = QJSRE("[[:space:]]*([[:digit:]]+):");
    auto tl = QJSRE("[[:space:]]*\\)");

    QJSREMatch re_match(2);
    QJSREIterator re_iterator(source);
    re_iterator.skip(pos);

    Node top;
    Node ast;

    while (!re_iterator.empty())
    {
      // Find the type of the node. If we didn't find a node, it's an error.
      if (!re_iterator.consume(hd, re_match))
      {
        auto loc = re_iterator.current();
        out << loc.origin_linecol() << "expected node" << std::endl
            << loc.str() << std::endl;
        return {};
      }

      // If we don't have a valid node type, it's an error.
      auto type_loc = re_match.at(1);
      auto type = detail::find_token(type_loc.view());

      if (type == Invalid)
      {
        out << type_loc.origin_linecol() << "unknown type" << std::endl
            << type_loc.str() << std::endl;
        return {};
      }

      // Find the source location of the node as a netstring.
      auto ident_loc = type_loc;

      if (re_iterator.consume(id, re_match))
      {
        auto len = re_match.parse<size_t>(1);
        ident_loc =
          Location(source, re_match.at().pos + re_match.at().len, len);
        re_iterator.skip(len);
      }

      // Push the node into the AST.
      auto node = NodeDef::create(type, ident_loc);

      if (ast)
        ast->push_back(node);
      else
        top = node;

      ast = node;

      // Skip the symbol table.
      re_iterator.consume(st, re_match);

      // `)` ends the node. Otherwise, we'll add children to this node.
      while (re_iterator.consume(tl, re_match))
      {
        auto parent = ast->parent();

        if (!parent)
          return ast;

        ast = parent->shared_from_this();
      }
    }

    // We never finished the AST, so it's an error.
    auto loc = re_iterator.current();
    out << loc.origin_linecol() << "incomplete AST" << std::endl
        << loc.str() << std::endl;
    return {};
  }

  using Regex = QJSRE;
  using REMatch = QJSREMatch;
  using REIterator = QJSREIterator;

  static inline bool full_match(const std::string_view& sv, const Regex& regex)
  {
    QJSREMatch m;
    return m.match(sv, regex);
  }
}
